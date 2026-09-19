"""Pure extraction acceptance; no Docker, provider or candidate execution."""
import ast
import importlib
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT/'measurements')):
    if entry not in sys.path:
        sys.path.insert(0, entry)


class SharedContract(unittest.TestCase):
    def leaf(self):
        self.assertIsNotNone(importlib.util.find_spec('contained_contract'),
                             'shared pure resource contract is missing')
        return importlib.import_module('contained_contract')

    def test_resource_rule_is_shared_by_runtime_and_readback(self):
        leaf = self.leaf()
        import contained_oci as runtime
        import kernel_readback as kr
        profile = dict(leaf.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertEqual(runtime.require_resource_profile_v2(profile), profile)
        self.assertEqual(kr.expected_readback(profile)['cpu_max'], [100000, 100000])
        with mock.patch.object(leaf, 'require_resource_profile_v2',
                               side_effect=leaf.ContractError('sentinel', code='resource-profile')):
            with self.assertRaises(runtime.PrepareError):
                runtime.require_resource_profile_v2(profile)
            with self.assertRaises(kr.ReadbackError):
                kr.expected_readback(profile)
            with self.assertRaises(kr.ReadbackError):
                kr.readback_record({}, profile)

    def test_resource_errors_have_finite_tags_and_legacy_messages(self):
        leaf = self.leaf()
        import contained_oci as runtime
        for update, tag in [({'pids': True}, 'resource-profile'),
                            ({'nofile_soft': 2048}, 'nofile'),
                            ({'cpu_rate_millicpu': 10**100}, 'cpu-rate')]:
            profile = dict(leaf.CANDIDATE_RESOURCE_PROFILE_V2, **update)
            with self.subTest(update=update):
                with self.assertRaises(leaf.ContractError) as a:
                    leaf.require_resource_profile_v2(profile)
                with self.assertRaises(runtime.PrepareError) as b:
                    runtime.require_resource_profile_v2(profile)
                self.assertEqual(a.exception.code, tag)
                self.assertEqual(str(a.exception), str(b.exception))

    def test_leaf_is_in_both_execution_identities(self):
        self.leaf()
        import sealed_measurement_contract as contracts
        import suggestion_evidence as ev
        for contract in (v for v in vars(contracts).values()
                         if isinstance(v, contracts.SealedMeasurementContract)):
            self.assertIn('contained_contract.py', contract.execution_paths)
            self.assertEqual(len(contract.execution_paths), 25)
        self.assertEqual(len(ev.SOURCE_PATHS), 30)
        self.assertEqual(ev.SOURCE_PATHS, tuple(sorted(set(ev._OWNED.execution_paths) | {
            'measurements/owned_suggestion_assessment.py', 'measurements/suggestion_admission.py',
            'measurements/suggestion_evidence.py', 'measurements/suggestion_execution.py',
            'measurements/suggestion_readback.py'})))

    def test_reader_dependency_closure_has_no_runtime_import(self):
        self.leaf()
        paths = [ROOT/'contained_contract.py'] + [ROOT/'measurements'/f'{n}.py' for n in
            ('kernel_readback', 'suggestion_evidence', 'sealed_measurement_contract', 'suggestion_readback')]
        forbidden = {'subprocess', 'contained_oci', 'bounded_run', 'corpus_adequacy',
                     'effective_envelope', 'envelope_collection'}
        for path in paths:
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) else [])
                self.assertFalse(forbidden.intersection(names), (path, names))

    def test_evaluator_profile_and_ceiling_are_leaf_bindings(self):
        leaf = self.leaf()
        import suggestion_evidence as ev
        self.assertIs(ev._CANDIDATE_RESOURCE_PROFILE_V2, leaf.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertIs(ev._DECLARED_CEILINGS, leaf.DECLARED_CEILINGS)


class SharedEnvelope(unittest.TestCase):
    def test_legacy_permission_delegates_to_one_pure_rule(self):
        import suggestion_evidence as ev
        import effective_envelope as legacy
        self.assertTrue(callable(getattr(ev, 'envelope_permission_data', None)),
                        'single pure permission rule is missing')
        with mock.patch.object(ev, 'envelope_permission_data', return_value=('withheld', 'sentinel')):
            self.assertEqual(legacy.publication_permission(setup_status='ready',
                envelope_status='verified', candidate_outcome='completed',
                cleanup='removed-and-absent'), ('withheld', 'sentinel'))

    def test_legacy_record_validator_reaches_shared_kernel(self):
        import suggestion_evidence as ev
        import effective_envelope as legacy
        self.assertTrue(callable(getattr(ev, 'require_envelope_record_data', None)),
                        'single pure record validator is missing')
        with mock.patch.object(ev, 'require_envelope_record_data',
                               side_effect=ev.EnvelopeContractError('sentinel')):
            with self.assertRaisesRegex(legacy.EnvelopeError, '^sentinel$'):
                legacy.validate_envelope_record({})


class ReadbackErrorBoundary(unittest.TestCase):
    def test_quota_predicate_errors_do_not_escape_readback_api(self):
        import contained_contract as leaf
        import kernel_readback as kr
        with mock.patch.object(leaf, 'cpu_quota_usec',
                               side_effect=leaf.ContractError('quota', code='cpu-rate')):
            with self.assertRaises(kr.ReadbackError):
                kr.expected_readback(leaf.CANDIDATE_RESOURCE_PROFILE_V2)


class ImportSentinel(unittest.TestCase):
    def test_fresh_reader_import_refuses_any_runtime_dependency(self):
        import subprocess
        code = '''import builtins,sys,json
sys.path[:0]=[sys.argv[1],sys.argv[1]+'/measurements']
original=builtins.__import__
forbidden={'subprocess','contained_oci','bounded_run','corpus_adequacy','effective_envelope','envelope_collection'}
def guarded(name,*args,**kwargs):
    if name in forbidden or name.startswith('aee_checker_sealed_'):
        raise AssertionError('runtime dependency: '+name)
    return original(name,*args,**kwargs)
builtins.__import__=guarded
import suggestion_readback
assert not forbidden.intersection(sys.modules)
print(json.dumps(sorted(n for n in sys.modules if n in {'suggestion_readback','suggestion_evidence','sealed_measurement_contract','contained_contract','kernel_readback'})))
'''
        result=subprocess.run([sys.executable,'-c',code,str(ROOT)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('contained_contract',result.stdout)
