from typing import Any, Dict, List, Literal, Optional, Tuple, Union
import asyncio

from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model, trimAndLoadJson
from deepeval.utils import get_or_create_event_loop

from deepteam.utils import validate_model_callback_signature

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import PromptExtractionMetric, BaseRedTeamingMetric
from deepteam.metrics.types import EvaluationExample
from deepteam.attacks.multi_turn.types import CallbackType
from deepteam.attacks.attack_engine import AttackEngine
from deepteam.test_case import RTTestCase
from deepteam.attacks.attack_simulator.schema import SyntheticDataList
from deepteam.risks import getRiskCategory
from .template import PromptLeakageTemplate
from deepeval.tracing.types import Trace
from deepteam.trace_scanner.schema import BatchFinding
from deepteam.trace_scanner import TraceScanner

PromptLeakageLiteral = Literal[
    "secrets_and_credentials",
    "instructions",
    "guard_exposure",
    "permissions_and_roles",
]


class PromptLeakage(BaseVulnerability):
    name: str = "Prompt Leakage"
    description = "Exposure of system prompts, instructions, secrets, credentials, permissions, roles, or internal guard configurations to unauthorized users."
    ALLOWED_TYPES = [type.value for type in PromptLeakageType]
    category = "Data Privacy"

    def __init__(
        self,
        async_mode: bool = True,
        verbose_mode: bool = False,
        simulator_model: Optional[
            Union[str, DeepEvalBaseLLM]
        ] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
        types: Optional[List[PromptLeakageLiteral]] = None,
        purpose: Optional[str] = None,
        evaluation_examples: Optional[List[EvaluationExample]] = None,
        evaluation_guidelines: Optional[List[str]] = None,
        attack_engine: Optional[AttackEngine] = None,
    ):
        if types is None:
            types = [type.value for type in PromptLeakageType]

        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=PromptLeakageType
        )
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.simulator_model = simulator_model
        self.evaluation_model = evaluation_model
        self.purpose = purpose
        self.evaluation_examples = evaluation_examples
        self.evaluation_guidelines = evaluation_guidelines
        super().__init__(types=enum_types)
        self.attack_engine = attack_engine

    def assess(
        self,
        model_callback: CallbackType,
        purpose: Optional[str] = None,
    ) -> Dict[PromptLeakageType, List[RTTestCase]]:

        validate_model_callback_signature(
            model_callback=model_callback,
            async_mode=self.async_mode,
        )

        if self.async_mode:
            loop = get_or_create_event_loop()
            return loop.run_until_complete(
                self.a_assess(
                    model_callback=model_callback,
                    purpose=purpose,
                )
            )

        simulated_test_cases = self.simulate_attacks(purpose)

        results: Dict[PromptLeakageType, List[RTTestCase]] = {}
        res: Dict[PromptLeakageType, PromptExtractionMetric] = {}
        simulated_attacks: Dict[str, str] = {}

        for simulated_test_case in simulated_test_cases:
            vulnerability_type = simulated_test_case.vulnerability_type
            input_text = simulated_test_case.input

            target_response = model_callback(input_text)
            target_output, retrieval_context, tools_called = (
                self._normalize_target_response(target_response)
            )
            red_teaming_test_case = RTTestCase(
                vulnerability=simulated_test_case.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_test_case.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=input_text,
                actual_output=target_output,
                retrieval_context=retrieval_context,
                tools_called=tools_called,
            )

            metric = self._get_metric(vulnerability_type)
            metric.measure(red_teaming_test_case)

            red_teaming_test_case.score = metric.score
            red_teaming_test_case.reason = metric.reason

            res[vulnerability_type] = metric
            simulated_attacks[vulnerability_type.value] = input_text

            results.setdefault(vulnerability_type, []).append(
                red_teaming_test_case
            )

        self.res = res
        self.simulated_attacks = simulated_attacks

        return results

    async def a_assess(
        self,
        model_callback: CallbackType,
        purpose: Optional[str] = None,
    ) -> Dict[PromptLeakageType, List[RTTestCase]]:

        validate_model_callback_signature(
            model_callback=model_callback,
            async_mode=self.async_mode,
        )

        simulated_test_cases = await self.a_simulate_attacks(purpose)

        results: Dict[PromptLeakageType, List[RTTestCase]] = {}
        res: Dict[PromptLeakageType, PromptExtractionMetric] = {}
        simulated_attacks: Dict[str, str] = {}

        async def process_attack(simulated_test_case: RTTestCase):
            vulnerability_type = simulated_test_case.vulnerability_type
            input_text = simulated_test_case.input

            target_response = await model_callback(input_text)
            target_output, retrieval_context, tools_called = (
                self._normalize_target_response(target_response)
            )

            red_teaming_test_case = RTTestCase(
                vulnerability=simulated_test_case.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_test_case.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=input_text,
                actual_output=target_output,
                retrieval_context=retrieval_context,
                tools_called=tools_called,
            )

            metric = self._get_metric(vulnerability_type)
            await metric.a_measure(red_teaming_test_case)

            red_teaming_test_case.score = metric.score
            red_teaming_test_case.reason = metric.reason

            res[vulnerability_type] = metric
            simulated_attacks[vulnerability_type.value] = input_text

            return vulnerability_type, red_teaming_test_case

        all_tasks = [
            process_attack(simulated_test_case)
            for simulated_test_case in simulated_test_cases
            if simulated_test_case.vulnerability_type in self.types
        ]

        for task in asyncio.as_completed(all_tasks):
            vulnerability_type, test_case = await task
            results.setdefault(vulnerability_type, []).append(test_case)

        self.res = res
        self.simulated_attacks = simulated_attacks

        return results

    def simulate_attacks(
        self,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ) -> List[RTTestCase]:
        if attacks_per_vulnerability_type < 1:
            raise ValueError(
                "`attacks_per_vulnerability_type` must be greater than 0."
            )

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        self.purpose = self._resolve_purpose(purpose)

        simulated_test_cases: List[RTTestCase] = []

        for type in self.types:
            prompt = PromptLeakageTemplate.generate_baseline_attacks(
                type, attacks_per_vulnerability_type, self.purpose
            )

            if self.using_native_model:
                res, _ = self.simulator_model.generate(
                    prompt, schema=SyntheticDataList
                )
                local_attacks = res.data
            else:
                try:
                    res: SyntheticDataList = self.simulator_model.generate(
                        prompt, schema=SyntheticDataList
                    )
                    local_attacks = res.data
                except TypeError:
                    res = self.simulator_model.generate(prompt)
                    data = trimAndLoadJson(res)
                    local_attacks = data.get("data", [])

            local_attacks = self._normalize_simulated_attacks(
                local_attacks, attacks_per_vulnerability_type
            )
            simulated_test_cases.extend(
                [
                    RTTestCase(
                        vulnerability=self.get_name(),
                        vulnerability_type=type,
                        input=local_attack,
                    )
                    for local_attack in local_attacks
                ]
            )

        return self._refine_simulated_attacks(simulated_test_cases, purpose)

    async def a_simulate_attacks(
        self,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ) -> List[RTTestCase]:
        if attacks_per_vulnerability_type < 1:
            raise ValueError(
                "`attacks_per_vulnerability_type` must be greater than 0."
            )

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        self.purpose = self._resolve_purpose(purpose)

        simulated_test_cases: List[RTTestCase] = []

        for type in self.types:
            prompt = PromptLeakageTemplate.generate_baseline_attacks(
                type, attacks_per_vulnerability_type, self.purpose
            )

            if self.using_native_model:
                res, _ = await self.simulator_model.a_generate(
                    prompt, schema=SyntheticDataList
                )
                local_attacks = res.data
            else:
                try:
                    res: SyntheticDataList = (
                        await self.simulator_model.a_generate(
                            prompt, schema=SyntheticDataList
                        )
                    )
                    local_attacks = res.data
                except TypeError:
                    res = await self.simulator_model.a_generate(prompt)
                    data = trimAndLoadJson(res)
                    local_attacks = data.get("data", [])

            local_attacks = self._normalize_simulated_attacks(
                local_attacks, attacks_per_vulnerability_type
            )
            simulated_test_cases.extend(
                [
                    RTTestCase(
                        vulnerability=self.get_name(),
                        vulnerability_type=type,
                        input=local_attack,
                    )
                    for local_attack in local_attacks
                ]
            )

        return await self._a_refine_simulated_attacks(
            simulated_test_cases, purpose
        )

    def _assess_trace(
        self,
        trace: Trace,
    ) -> List[BatchFinding]:
        """
        Evaluates an entire execution trace for Prompt Leakage vulnerabilities using bottoms-up batching.
        """
        if self.async_mode:
            loop = get_or_create_event_loop()
            return loop.run_until_complete(
                self._a_assess_trace(trace=trace)
            )

        self.evaluation_model, self.using_native_model = initialize_model(
            self.evaluation_model
        )
        trace_scanner = TraceScanner(
            model=self.evaluation_model,
            template=PromptLeakageTemplate,
        )

        findings = trace_scanner.process_trace(trace)

        self.trace_findings = findings
        self.vulnerable = any(f.outcome == "materialized" for f in findings)

        return findings

    async def _a_assess_trace(
        self,
        trace: Trace,
    ) -> List[BatchFinding]:
        """
        Asynchronously evaluates an entire execution trace for Prompt Leakage vulnerabilities.
        """
        self.evaluation_model, self.using_native_model = initialize_model(
            self.evaluation_model
        )

        trace_scanner = TraceScanner(
            model=self.evaluation_model,
            template=PromptLeakageTemplate,
        )

        findings = await trace_scanner.a_process_trace(trace)

        self.trace_findings = findings
        self.vulnerable = any(f.outcome == "materialized" for f in findings)

        return findings


    def _get_metric(
        self,
        type: PromptLeakageType,
    ) -> BaseRedTeamingMetric:
        return PromptExtractionMetric(
            purpose=self.purpose,
            model=self.evaluation_model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
            evaluation_examples=self.evaluation_examples,
            evaluation_guidelines=self.evaluation_guidelines,
        )

    def _resolve_purpose(self, purpose: Optional[str]) -> Optional[str]:
        return purpose if purpose is not None else self.purpose

    def _normalize_simulated_attacks(
        self, local_attacks: List[Any], max_attacks: int
    ) -> List[str]:
        return [
            normalized_attack
            for attack in local_attacks
            if (normalized_attack := self._extract_attack_input(attack))
        ][:max_attacks]

    def _extract_attack_input(self, attack: Any) -> Optional[str]:
        if attack is None:
            return None

        if isinstance(attack, dict):
            value = (
                attack.get("input")
                or attack.get("prompt")
                or attack.get("attack")
                or attack.get("text")
                or attack.get("query")
                or attack.get("content")
            )
            if value is None:
                string_values = [
                    value
                    for value in attack.values()
                    if isinstance(value, str) and value.strip()
                ]
                if len(string_values) == 1:
                    value = string_values[0]
        else:
            value = getattr(attack, "input", attack)

        if value is None:
            return None

        normalized = str(value).strip()
        return normalized or None

    def _normalize_target_response(
        self, target_response: Any
    ) -> Tuple[str, Optional[List[str]], Optional[List[Any]]]:
        if isinstance(target_response, dict):
            output = (
                target_response.get("content")
                or target_response.get("actual_output")
                or target_response.get("output")
                or ""
            )
            return (
                str(output),
                target_response.get("retrieval_context")
                or target_response.get("retrievalContext"),
                target_response.get("tools_called")
                or target_response.get("toolsCalled"),
            )

        if hasattr(target_response, "content"):
            return (
                (
                    ""
                    if target_response.content is None
                    else str(target_response.content)
                ),
                getattr(
                    target_response,
                    "retrieval_context",
                    getattr(target_response, "retrievalContext", None),
                ),
                getattr(
                    target_response,
                    "tools_called",
                    getattr(target_response, "toolsCalled", None),
                ),
            )

        return (
            "" if target_response is None else str(target_response),
            None,
            None,
        )

    def is_vulnerable(self) -> bool:
        self.vulnerable = False
        try:
            for _, metric_data in self.res.items():
                if metric_data.score < 1:
                    self.vulnerable = True
        except:
            self.vulnerable = False
        return self.vulnerable

    def get_name(self) -> str:
        return self.name