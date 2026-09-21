"""A real unique-anchor substitution owns execution, not backend labels."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_adequacy as ca


class SharedExecutionPrimitive(unittest.TestCase):
    def session(self, root, backend=None):
        source = root / 'subject.py'
        source.write_text('import json, sys\nVALUE = 7\nsys.stdout.buffer.write((json.dumps({"value": VALUE}) + "\\n").encode("utf-8"))\n')
        vector = root / 'vector.json'; vector.write_text('{}\n')
        manifest = {'_repo_root': root, '_source_paths': [source], 'runner': 'process',
                    'entrypoint_command': [sys.executable, 'subject.py', '{vector}'],
                    'vector_timeout': 3, 'build_timeout': 3, 'build': None,
                    'id_key': 'id', 'vector_path_key': 'path', 'outcome_parse': 'json',
                    'outcome_from': 'value', 'diagnostic_from': None,
                    'accepted_exit_codes': [0], 'unproved_exit_codes': []}
        session = ca._ProcessMutationSession(manifest, backend or ca._default_execution_backend, None, {}, 0)
        session.baselines['g'] = ([{'id': 'one', 'path': 'vector.json'}], {}, {})
        return session, source

    def test_real_source_substitution_and_restoration_without_score_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            session, source = self.session(Path(tmp)); original = source.read_bytes()
            baseline = session.execute(session.baselines['g'][0], step=ca._step('baseline', 'g'))
            self.assertEqual(baseline.outcomes, {'one': 7})
            with mock.patch.object(ca, '_record_control', side_effect=AssertionError('comparison')):
                facts = ca._execute_mutation_observation(session, 'g',
                    {'label': 'change', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 8', 'control': True})
            self.assertEqual(facts['execution'].outcomes, {'one': 8})
            self.assertEqual(facts['anchor_hits'], 1)
            self.assertTrue(facts['restored'])
            self.assertEqual(source.read_bytes(), original)
            # Metadata alone does not change the executed source.
            result = session.execute(session.baselines['g'][0], step=ca._step('mutant', 'g', 'change'))
            self.assertEqual(result.outcomes, {'one': 7})

    def test_missing_or_duplicate_anchor_has_no_backend_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            session, source = self.session(Path(tmp))
            session.backend = mock.Mock(side_effect=AssertionError('backend reached'))
            for anchor in ('missing', 'json'):
                facts = ca._execute_mutation_observation(session, 'g',
                    {'label': 'bad', 'anchor': anchor, 'replacement': '8'})
                self.assertNotEqual(facts['anchor_hits'], 1)
                self.assertIsNone(facts['execution'])
                self.assertEqual(facts['application'], 'failed')
            session.backend.assert_not_called()

    def test_exception_restores_original_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            session, source = self.session(Path(tmp)); original = source.read_bytes()
            session.backend = mock.Mock(side_effect=RuntimeError('interrupted'))
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                ca._execute_mutation_observation(session, 'g',
                    {'label': 'change', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 8'})
            self.assertEqual(source.read_bytes(), original)

    def test_backend_source_write_is_refused_and_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            session, source = self.session(Path(tmp)); original = source.read_bytes()
            def bad_backend(m, vectors, **kwargs):
                m['_source_paths'][0].write_text('forged\n')
                return ca._ProcessExecution(True, 'fake', {'one': 8}, {}, {}, {})
            session.backend = bad_backend
            with self.assertRaisesRegex(ca.ManifestError, 'changed a declared source'):
                ca._execute_mutation_observation(session, 'g',
                    {'label': 'change', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 8'})
            self.assertEqual(source.read_bytes(), original)



class RawChildCapture(unittest.TestCase):
    def test_raw_crlf_is_not_normalized(self):
        import bounded_run as br
        command = [sys.executable, '-c', 'import os; os.write(1, b"row\\r\\n")']
        result = br.run_capped_bytes(command, Path.cwd(), 3)
        self.assertEqual(result.stdout, b'row\r\n')

    def test_invalid_utf8_retains_actual_bytes_and_legacy_returns_text(self):
        import bounded_run as br
        command = [sys.executable, '-c', 'import os; os.write(1, bytes([255, 0, 10])); os.write(2, b"err")']
        result = br.run_capped_bytes(command, Path.cwd(), 3)
        self.assertEqual(result.stdout, b'\xff\x00\n')
        self.assertEqual(result.stderr, b'err')
        legacy = br._run_capped(command, Path.cwd(), 3)
        self.assertEqual(legacy.stdout, '\ufffd\x00\n')
        self.assertEqual(legacy.stderr, 'err')

    def test_cap_preserves_bounded_prefix_and_legacy_exception(self):
        import bounded_run as br
        command = [sys.executable, '-c', 'import os; os.write(1, b"x" * 65536)']
        with mock.patch.object(br, 'OUTPUT_CAP_BYTES', 4096):
            with self.assertRaises(br.RawTermination) as caught:
                br.run_capped_bytes(command, Path.cwd(), 3)
            self.assertEqual(caught.exception.reason, 'output-cap')
            self.assertEqual(caught.exception.stdout, b'x' * 4096)
            self.assertEqual(caught.exception.stderr, b'')
            with self.assertRaises(br._OutputTooLarge): br._run_capped(command, Path.cwd(), 3)

    def test_timeout_retains_prefix_and_no_successful_projection(self):
        import bounded_run as br
        command = [sys.executable, '-c', 'import os,time; os.write(1,b"{\\"value\\":7}"); time.sleep(5)']
        with self.assertRaises(br.RawTermination) as caught:
            br.run_capped_bytes(command, Path.cwd(), 0.2)
        self.assertEqual(caught.exception.reason, 'timeout')
        self.assertEqual(caught.exception.stdout, b'{"value":7}')
        self.assertIsInstance(caught.exception.cause, __import__('subprocess').TimeoutExpired)

    def test_spawn_failure_is_empty_capture_not_fabricated_output(self):
        import bounded_run as br
        with self.assertRaises(br.RawTermination) as caught:
            br.run_capped_bytes(['/nonexistent/ca-observation-child'], Path.cwd(), 3)
        self.assertEqual(caught.exception.reason, 'incomplete')
        self.assertEqual((caught.exception.stdout, caught.exception.stderr), (b'', b''))


class ObservationReceipts(unittest.TestCase):
    def setUp(self):
        import observation_session as obs
        self.obs = obs
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        old, self.source = SharedExecutionPrimitive().session(Path(self.tmp.name))
        self.session = obs.ObservationSession(old.manifest, obs.LocalObservationBackend())
        self.vectors = old.baselines['g'][0]
        self.session.baselines['g'] = (self.vectors, {}, {})
        self.session.step_id = 'baseline-0'

    def execute(self):
        return self.session.execute(self.vectors, step=ca._step('baseline', 'g'))

    def test_raw_bytes_are_bound_before_projection_and_ids_are_fresh(self):
        first = self.execute(); second = self.execute()
        self.assertEqual(first.process.outcomes, {'one': 7})
        self.assertEqual(first.receipts[0].raw_stdout, b'{"value": 7}\n')
        self.assertEqual(first.receipts[0].raw_sha256, 'sha256:' + __import__('hashlib').sha256(b'{"value": 7}\n').hexdigest())
        self.assertEqual(first.receipts[0].raw_sha256, second.receipts[0].raw_sha256)
        self.assertNotEqual(first.receipts[0].invocation_id, second.receipts[0].invocation_id)

    def test_real_substitution_uses_same_primitive_with_raw_receipts(self):
        self.session.step_id = 'control-1'
        original = self.source.read_bytes()
        result = ca._execute_mutation_observation(self.session, 'g',
            {'label': 'change', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 8', 'control': True})
        self.assertEqual(result['execution'].process.outcomes, {'one': 8})
        self.assertEqual(self.source.read_bytes(), original)
        self.assertNotEqual(result['execution'].receipts[0].source_sha256,
                            self.obs.source_digest(self.session.manifest))

    def test_legacy_result_and_forged_receipts_refuse(self):
        from dataclasses import replace
        local = self.obs.LocalObservationBackend()
        for defect in ('legacy', 'missing', 'duplicate', 'wrong-step', 'wrong-source', 'projected-hash', 'forged-outcome'):
            def backend(m, vectors, *, rebuild=True, step, observation):
                result = local(m, vectors, rebuild=rebuild, step=step, observation=observation)
                if defect == 'legacy': return result.process
                if defect == 'missing': return replace(result, receipts=())
                if defect == 'duplicate': return replace(result, receipts=result.receipts*2)
                if defect == 'forged-outcome':
                    result.process.outcomes['one'] = 999
                    return result
                receipt = result.receipts[0]
                if defect == 'wrong-step': receipt = replace(receipt, step_id='other')
                if defect == 'wrong-source': receipt = replace(receipt, source_sha256='sha256:'+'f'*64)
                if defect == 'projected-hash': receipt = replace(receipt, raw_sha256='sha256:' + __import__('hashlib').sha256(json.dumps(result.process.outcomes).encode()).hexdigest())
                return replace(result, receipts=(receipt,))
            backend.accepts_step = True
            self.session.backend = backend
            with self.subTest(defect=defect), self.assertRaises(ca.ManifestError): self.execute()

    def test_retained_execution_cannot_replay_on_new_invocation(self):
        result = self.execute()
        def replay(*args, **kwargs): return result
        replay.accepts_step = True
        self.session.backend = replay
        with self.assertRaises(ca.ManifestError): self.execute()

    def test_detaches_mutable_backend_outcomes(self):
        retained = []
        local = self.obs.LocalObservationBackend()
        def backend(*args, **kwargs):
            result = local(*args, **kwargs); retained.append(result); return result
        backend.accepts_step = True
        self.session.backend = backend
        result = self.execute()
        retained[0].process.outcomes['one'] = 999
        self.assertEqual(result.process.outcomes, {'one': 7})

    def test_source_changed_during_request_binding_is_refused_before_child(self):
        original = self.source.read_bytes()
        real_digest = self.obs.source_digest
        def raced(manifest):
            digest = real_digest(manifest)
            self.source.write_text('print("{\\"value\\":999}")\n')
            return digest
        with mock.patch.object(self.obs, 'source_digest', side_effect=raced), mock.patch.object(
                self.obs, 'run_capped_bytes', side_effect=AssertionError('child started')):
            with self.assertRaises(ca.ManifestError): self.execute()
        self.assertEqual(self.source.read_bytes(), original)

    def test_build_has_no_vector_receipt(self):
        result = self.session.execute(None, step=ca._step('build'))
        self.assertTrue(result.process.built)
        self.assertEqual(result.receipts, ())

    def test_missing_selector_is_abnormal_never_null_equality(self):
        self.source.write_text('print("{}")\n')
        result = self.execute()
        self.assertEqual(result.process.outcomes, {})
        self.assertEqual(result.process.raised, {'one': 'selector-missing'})
        self.assertEqual(result.receipts[0].selector_presence, (False, True))

    def test_abnormal_child_is_not_parsed_and_stops_remaining_vectors(self):
        self.source.write_text('import sys\nprint("{\\"value\\":7}")\nsys.exit(3)\n')
        self.vectors.append({'id': 'two', 'path': 'vector.json'})
        result = self.execute()
        self.assertEqual(result.process.outcomes, {})
        self.assertEqual(result.process.raised, {'one': 'unexpected-exit'})
        self.assertEqual(len(result.receipts), 1)


if __name__ == '__main__': unittest.main()
