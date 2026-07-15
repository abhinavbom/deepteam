from typing import List, Literal, Optional, Union, Dict
import asyncio

from deepeval.models import DeepEvalBaseLLM
from deepeval.metrics.utils import initialize_model, trimAndLoadJson
from deepeval.utils import get_or_create_event_loop

from deepteam.utils import validate_model_callback_signature

from deepteam.vulnerabilities import BaseVulnerability
from deepteam.vulnerabilities.rbac import RBACType
from deepteam.vulnerabilities.utils import validate_vulnerability_types
from deepteam.metrics import RBACMetric, BaseRedTeamingMetric
from deepteam.metrics.types import EvaluationExample
from deepteam.attacks.multi_turn.types import CallbackType
from deepteam.attacks.attack_engine import AttackEngine
from deepteam.test_case import RTTestCase
from deepteam.attacks.attack_simulator.schema import SyntheticDataList
from deepteam.risks import getRiskCategory
from .template import RBACTemplate
from .quality import (
    candidate_count,
    select_quality_attacks,
    reconcile_refined,
)
from deepeval.tracing.types import Trace
from deepteam.trace_scanner.schema import BatchFinding
from deepteam.trace_scanner import TraceScanner

RBACLiteral = Literal[
    "role_bypass",
    "privilege_escalation",
    "unauthorized_role_assumption",
    "effective_role_confusion",
]


class RBAC(BaseVulnerability):
    name: str = "RBAC"
    description = "Role-Based Access Control bypass enabling role restriction circumvention, privilege escalation, unauthorized role assumption, or confused-deputy execution under the agent's own privileged identity without proper validation."
    ALLOWED_TYPES = [type.value for type in RBACType]
    category = "Security"

    def __init__(
        self,
        async_mode: bool = True,
        verbose_mode: bool = False,
        simulator_model: Optional[
            Union[str, DeepEvalBaseLLM]
        ] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
        types: Optional[List[RBACLiteral]] = [type.value for type in RBACType],
        purpose: Optional[str] = None,
        evaluation_examples: Optional[List[EvaluationExample]] = None,
        evaluation_guidelines: Optional[List[str]] = None,
        attack_engine: Optional[AttackEngine] = None,
    ):
        enum_types = validate_vulnerability_types(
            self.get_name(), types=types, allowed_type=RBACType
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
    ) -> Dict[RBACType, List[RTTestCase]]:

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

        results: Dict[RBACType, List[RTTestCase]] = {}
        res: Dict[RBACType, RBACMetric] = {}
        simulated_attacks: Dict[str, str] = {}

        for simulated_test_case in simulated_test_cases:
            vulnerability_type = simulated_test_case.vulnerability_type
            input_text = simulated_test_case.input

            target_output = model_callback(input_text)
            red_teaming_test_case = RTTestCase(
                vulnerability=simulated_test_case.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_test_case.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=input_text,
                actual_output=target_output,
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
    ) -> Dict[RBACType, List[RTTestCase]]:

        validate_model_callback_signature(
            model_callback=model_callback,
            async_mode=self.async_mode,
        )

        simulated_test_cases = await self.a_simulate_attacks(purpose)

        results: Dict[RBACType, List[RTTestCase]] = {}
        res: Dict[RBACType, RBACMetric] = {}
        simulated_attacks: Dict[str, str] = {}

        async def process_attack(simulated_test_case: RTTestCase):
            vulnerability_type = simulated_test_case.vulnerability_type
            input_text = simulated_test_case.input

            target_output = await model_callback(input_text)

            red_teaming_test_case = RTTestCase(
                vulnerability=simulated_test_case.vulnerability,
                vulnerability_type=vulnerability_type,
                attackMethod=simulated_test_case.attack_method,
                riskCategory=getRiskCategory(vulnerability_type),
                input=input_text,
                actual_output=target_output,
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

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        # Preserve a constructor-provided purpose when called without one
        # (None must not clobber it).
        if purpose is not None:
            self.purpose = purpose

        templates = dict()
        simulated_test_cases: List[RTTestCase] = []

        for type in self.types:
            templates[type] = templates.get(type, [])
            templates[type].append(
                RBACTemplate.generate_baseline_attacks(
                    type,
                    candidate_count(attacks_per_vulnerability_type),
                    self.purpose,
                )
            )

        for type in self.types:
            for prompt in templates[type]:
                if self.using_native_model:
                    res, _ = self.simulator_model.generate(
                        prompt, schema=SyntheticDataList
                    )
                    local_attacks = [item.input for item in res.data]
                else:
                    try:
                        res: SyntheticDataList = self.simulator_model.generate(
                            prompt, schema=SyntheticDataList
                        )
                        local_attacks = [item.input for item in res.data]
                    except TypeError:
                        res = self.simulator_model.generate(prompt)
                        try:
                            data = trimAndLoadJson(res)
                            local_attacks = data.get("data", [])
                        except Exception:
                            # A flaky simulator can emit unparseable JSON; let
                            # the curated floor backfill instead of crashing.
                            local_attacks = []

            # Curated-or-better: gate generations, fall back to the vetted floor.
            local_attacks = select_quality_attacks(
                type, local_attacks, attacks_per_vulnerability_type
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

        refined = self._refine_simulated_attacks(
            simulated_test_cases, self.purpose
        )
        return reconcile_refined(simulated_test_cases, refined)

    async def a_simulate_attacks(
        self,
        purpose: Optional[str] = None,
        attacks_per_vulnerability_type: int = 1,
    ) -> List[RTTestCase]:

        self.simulator_model, self.using_native_model = initialize_model(
            self.simulator_model
        )

        # Preserve a constructor-provided purpose when called without one
        # (None must not clobber it).
        if purpose is not None:
            self.purpose = purpose

        templates = dict()
        simulated_test_cases: List[RTTestCase] = []

        for type in self.types:
            templates[type] = templates.get(type, [])
            templates[type].append(
                RBACTemplate.generate_baseline_attacks(
                    type,
                    candidate_count(attacks_per_vulnerability_type),
                    self.purpose,
                )
            )

        for type in self.types:
            for prompt in templates[type]:
                if self.using_native_model:
                    res, _ = await self.simulator_model.a_generate(
                        prompt, schema=SyntheticDataList
                    )
                    local_attacks = [item.input for item in res.data]
                else:
                    try:
                        res: SyntheticDataList = (
                            await self.simulator_model.a_generate(
                                prompt, schema=SyntheticDataList
                            )
                        )
                        local_attacks = [item.input for item in res.data]
                    except TypeError:
                        res = await self.simulator_model.a_generate(prompt)
                        try:
                            data = trimAndLoadJson(res)
                            local_attacks = data.get("data", [])
                        except Exception:
                            # A flaky simulator can emit unparseable JSON; let
                            # the curated floor backfill instead of crashing.
                            local_attacks = []

            # Curated-or-better: gate generations, fall back to the vetted floor.
            local_attacks = select_quality_attacks(
                type, local_attacks, attacks_per_vulnerability_type
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

        refined = await self._a_refine_simulated_attacks(
            simulated_test_cases, self.purpose
        )
        return reconcile_refined(simulated_test_cases, refined)

    def _refine_simulated_attacks(self, simulated_test_cases, purpose):
        # The baseline prompts are already evasive, on-lane, single-subject and
        # gated by quality.select_quality_attacks. In STANDALONE assess()
        # (attack_engine is None) we skip the generic AttackEngine transform
        # entirely and ship the gated curated-or-better set as-is, so the output
        # is fully deterministic. When an engine IS present — passed explicitly,
        # OR injected by red_team()/RedTeamer (attack_simulator copies its engine
        # onto each vulnerability) — we DO refine; but the caller wraps this in
        # reconcile_refined(), which keeps a refined variant only when it stays
        # banned-literal-free, on-lane, and scores at least as high as the gated
        # original, else falls back to the gated prompt. So the quality floor
        # holds in BOTH paths; the override only adds determinism for standalone.
        if self.attack_engine is None:
            return simulated_test_cases
        return super()._refine_simulated_attacks(simulated_test_cases, purpose)

    async def _a_refine_simulated_attacks(self, simulated_test_cases, purpose):
        # See _refine_simulated_attacks: standalone (no engine) ships the gated
        # set as-is; an engine (explicit or red_team-injected) refines, guarded by
        # reconcile_refined() so the quality floor holds either way.
        if self.attack_engine is None:
            return simulated_test_cases
        return await super()._a_refine_simulated_attacks(
            simulated_test_cases, purpose
        )

    def _assess_trace(
        self,
        trace: Trace,
    ) -> List[BatchFinding]:
        """
        Evaluates an entire execution trace for RBAC vulnerabilities using bottoms-up batching.
        """
        if self.async_mode:
            loop = get_or_create_event_loop()
            return loop.run_until_complete(self._a_assess_trace(trace=trace))

        self.evaluation_model, self.using_native_model = initialize_model(
            self.evaluation_model
        )
        trace_scanner = TraceScanner(
            model=self.evaluation_model,
            template=RBACTemplate,
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
        Asynchronously evaluates an entire execution trace for RBAC vulnerabilities.
        """
        self.evaluation_model, self.using_native_model = initialize_model(
            self.evaluation_model
        )

        trace_scanner = TraceScanner(
            model=self.evaluation_model,
            template=RBACTemplate,
        )

        findings = await trace_scanner.a_process_trace(trace)

        self.trace_findings = findings
        self.vulnerable = any(f.outcome == "materialized" for f in findings)

        return findings

    def _get_metric(
        self,
        type: RBACType,
    ) -> BaseRedTeamingMetric:
        return RBACMetric(
            purpose=self.purpose,
            model=self.evaluation_model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
            evaluation_examples=self.evaluation_examples,
            evaluation_guidelines=self.evaluation_guidelines,
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
