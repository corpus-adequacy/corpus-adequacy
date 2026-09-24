"""Public baseline-only execution must retain the ordinary prefix guarantees."""
import copy
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_adequacy as ca
import execution_observation as codec
import observation_session as obs
from test_observation_prefix import corpus, D, E
from test_observation_resume import make_admission


@unittest.skipIf(ca.fcntl is None, 'observation execution requires POSIX advisory locks')
class BaselineOnly(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = corpus(self.root / 'subject', count=3)

    def run_prefix(self, **changes):
        self.assertIn('stop_before', inspect.signature(obs.observe_prefix).parameters)
        args = dict(execution_profile='trusted-local', context_raw=b'baseline-only',
                    output_root=self.root/'evidence', policy_identity=D,
                    interpreter_identity=E, stop_before='control', vector_ids=['v1'])
        args.update(changes)
        return obs.observe_prefix(self.manifest, **args)

    def test_selected_baseline_is_isolated_persisted_and_closed_before_controls(self):
        calls = []; receipts = []
        original = (self.manifest.parent/'subject.py').read_bytes()

        class Backend(obs.LocalObservationBackend):
            backend_identity = D
            environment_identity = E

            def __call__(self, manifest, vectors=None, **kwargs):
                calls.append((Path(manifest['_repo_root']), copy.deepcopy(vectors)))
                return super().__call__(manifest, vectors, **kwargs)

        def verified(receipt, path):
            self.assertEqual(codec.sha256(path.read_bytes()), receipt.evidence_sha256)
            receipts.append(receipt.vector_id)

        with mock.patch.object(ca, '_execute_mutation_observation',
                               side_effect=AssertionError('mutation dispatched')):
            path = self.run_prefix(backend=Backend(), on_verified_receipt=verified,
                                   vector_ids=['v2', 'v0'])
        doc = codec.load_observation(path.read_bytes(), kind='prefix')
        self.assertEqual(receipts, ['v0', 'v2'])  # corpus order, not caller order
        self.assertEqual(doc['phase'], 'stopped')
        self.assertEqual(doc['closure']['reason'], 'operator-refused')
        self.assertEqual([s['state'] for s in doc['steps']],
                         ['complete', 'complete', 'stopped', 'not_run', 'not_run'])
        self.assertEqual([s['outcome'] for s in doc['steps'][1]['slots']], [7, 7])
        self.assertTrue(all(s['receipt'] is None for step in doc['steps'][2:]
                            for s in step['slots']))
        self.assertTrue(doc['cleanup']['restored'])
        self.assertTrue(doc['cleanup']['isolated_tree_removed'])
        self.assertTrue(all(root != self.manifest.parent and not root.exists()
                            for root, _ in calls))
        self.assertEqual((self.manifest.parent/'subject.py').read_bytes(), original)
        self.assertTrue((path.parent/'intent.json').is_file())
        self.assertEqual(len(list(path.parent.glob('receipt-*.json'))), 2)
        stop = doc['steps'][2]['failure']
        raw = (path.parent/'blobs'/stop['evidence_sha256'].removeprefix('sha256:')).read_bytes()
        self.assertEqual(codec.sha256(raw), stop['evidence_sha256'])
        self.assertEqual(json.loads(raw)['vector_ids'], ['v0', 'v2'])
        closed = codec.load_observation(codec.prepare_closure(path.read_bytes()), kind='final')
        self.assertEqual(closed['phase'], 'stopped')

    def test_missing_positive_control_refuses_before_backend_or_evidence(self):
        manifest = json.loads(self.manifest.read_bytes())
        manifest['mutants']['g'] = [m for m in manifest['mutants']['g']
                                     if m['label'] != 'positive']
        self.manifest.write_text(json.dumps(manifest))
        with mock.patch.object(obs.LocalObservationBackend, '__call__',
                               side_effect=AssertionError('backend dispatched')):
            with self.assertRaisesRegex(ca.ManifestError, 'control'):
                self.run_prefix()
        self.assertFalse((self.root/'evidence').exists())

    def test_invalid_selections_refuse_before_effects(self):
        for selection in ([], ['v1', 'v1'], ['absent'], 'v1', [True], [None]):
            with self.subTest(selection=selection), self.assertRaises(ca.ManifestError):
                self.run_prefix(vector_ids=selection)
        self.assertFalse((self.root/'evidence').exists())

    def test_unknown_id_among_known_vectors_refuses_before_effects(self):
        with mock.patch.object(obs.LocalObservationBackend, '__call__',
                               side_effect=AssertionError('backend dispatched')):
            with self.assertRaisesRegex(ca.ManifestError, 'names an unknown vector'):
                self.run_prefix(vector_ids=['v1', 'absent'])
        self.assertFalse((self.root/'evidence').exists())

    def test_stop_evidence_binds_boundary_selection_and_operator_context(self):
        context = b'operator-selected baseline context'
        path = self.run_prefix(context_raw=context, vector_ids=['v2', 'v0'])
        doc = codec.load_observation(path.read_bytes(), kind='prefix')
        stop = doc['steps'][2]['failure']
        raw = (path.parent/'blobs'/stop['evidence_sha256'].removeprefix('sha256:')).read_bytes()
        self.assertEqual(codec.sha256(raw), stop['evidence_sha256'])
        self.assertEqual(json.loads(raw), {
            'schema': 'corpus-adequacy.observation-operator-stop.v0',
            'reason': 'operator-refused',
            'stop_before': 'control',
            'context_sha256': codec.sha256(context),
            'vector_ids': ['v0', 'v2'],
        })
        self.assertEqual(doc['bindings']['context_sha256'], codec.sha256(context))

    def test_selection_cannot_change_normal_resumable_prefix(self):
        with self.assertRaises(ca.ManifestError):
            self.run_prefix(stop_before=None)
        self.assertFalse((self.root/'evidence').exists())

    def test_unknown_boundary_and_competing_control_hook_refuse(self):
        for boundary in ('ordinary', 'baseline', [], True):
            with self.subTest(boundary=boundary), self.assertRaises(ca.ManifestError):
                self.run_prefix(stop_before=boundary)
        with self.assertRaises(ca.ManifestError):
            self.run_prefix(control_preflight=lambda *args: None)
        self.assertFalse((self.root/'evidence').exists())

    def test_manifest_cannot_request_operator_selection_or_stop(self):
        original = json.loads(self.manifest.read_bytes())
        for key, value in (('stop_before', 'control'), ('vector_ids', ['v1'])):
            self.manifest.write_text(json.dumps({**original, key: value}))
            with self.subTest(key=key), self.assertRaises(ca.ManifestError):
                self.run_prefix()
        self.assertFalse((self.root/'evidence').exists())

    def test_selection_cannot_drop_a_declared_group(self):
        manifest = json.loads(self.manifest.read_bytes())
        manifest['mutants']['other'] = copy.deepcopy(manifest['mutants']['g'])
        for mutant in manifest['mutants']['other']:
            mutant['label'] = 'other-' + mutant['label']
        manifest['group_key'] = 'group'
        self.manifest.write_text(json.dumps(manifest))
        vectors = json.loads((self.manifest.parent/'vectors.json').read_bytes())
        for vector in vectors:
            vector['group'] = 'g'
        vectors[-1]['group'] = 'other'
        (self.manifest.parent/'vectors.json').write_text(json.dumps(vectors))
        with self.assertRaisesRegex(ca.ManifestError, 'retain every declared group'):
            self.run_prefix()
        self.assertFalse((self.root/'evidence').exists())
        path = self.run_prefix(vector_ids=['v1', 'v2'])
        doc = codec.load_observation(path.read_bytes(), kind='prefix')
        self.assertEqual(doc['phase'], 'stopped')
        self.assertEqual([row['vector_ids'] for row in doc['schedule']
                          if row['kind'] == 'baseline'], [['v1'], ['v2']])

    def test_selection_changes_evidence_binding_and_default_selects_all(self):
        first = codec.load_observation(self.run_prefix().read_bytes(), kind='prefix')
        second = codec.load_observation(self.run_prefix(
            output_root=self.root/'all-evidence', vector_ids=None).read_bytes(), kind='prefix')
        self.assertNotEqual(first['bindings']['corpus_sha256'], second['bindings']['corpus_sha256'])
        self.assertEqual(second['schedule'][1]['vector_ids'], ['v0', 'v1', 'v2'])

    def test_receipt_hook_interruption_leaves_no_prefix_or_later_dispatch(self):
        def fail(receipt, path):
            raise RuntimeError('retain interruption')
        with self.assertRaisesRegex(RuntimeError, 'retain interruption'):
            self.run_prefix(vector_ids=['v0', 'v1'], on_verified_receipt=fail)
        root = next((self.root/'evidence').iterdir())
        self.assertFalse((root/'prefix.json').exists())
        self.assertTrue((root/'interrupted.json').exists())
        self.assertEqual(len(list(root.glob('receipt-*.json'))), 1)

    def test_baseline_only_prefix_cannot_be_admitted_or_resumed(self):
        prefix = self.run_prefix(context_raw=b'context')
        admission = make_admission(prefix)
        with mock.patch.object(obs.LocalObservationBackend, '__call__',
                               side_effect=AssertionError('resumed backend')):
            with self.assertRaisesRegex(ValueError, 'not awaiting admission'):
                obs.resume_observation(prefix, admission, context_raw=b'context',
                    decision_raw=b'decision', manifest_path=self.manifest,
                    execution_profile='trusted-local', backend=None, ledger_root=self.root/'ledger',
                    output_root=self.root/'final')
        self.assertFalse((self.root/'final').exists())
