import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import corpus_adequacy as ca

MISSING = object()

def measure(before, after, expected=MISSING, raised=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / 'source.txt'
        source.write_text('ANCHOR')
        mutant = dict(label='rule', anchor='ANCHOR', replacement='CHANGED')
        if expected is not MISSING:
            mutant['expected_mover'] = expected
        manifest = dict(schema=ca.SCHEMA, runner='batch',
                        outcome_parse='test-names', vectors='vectors.json',
                        implementation_sources=['source.txt'],
                        entrypoint_command=['NEVER-EXECUTE'], accepted_exit_codes=[0, 101],
                        mutants={'all': [mutant]})
        manifest = ca.load_manifest_bytes(json.dumps(manifest).encode(),
                                          root / 'manifest.json')
        def parsed(names):
            output = ''.join('test %s ... FAILED\n' % n for n in names)
            output += 'test result: ok. 1 passed\n'
            value, diag, kind = ca.child_outcome(
                manifest, subprocess.CompletedProcess([], 101 if names else 0,
                                                       output, ''))
            assert kind is None
            return value
        old, new = parsed(before), parsed(after)
        tally = ca._new_process_tally()
        result = ca._ProcessExecution(True, 'synthetic',
                  {} if raised else {'<batch>': new}, {}, raised or {}, {})
        session = SimpleNamespace(manifest=manifest,
            accumulator=SimpleNamespace(state=tally), acknowledged={},
            baselines={'all': ([], {'<batch>': old}, {})},
            execute=lambda *args, **kwargs: result)
        with mock.patch.object(ca.subprocess, 'Popen',
                               side_effect=AssertionError('no subprocess')):
            ca._run_mutation_step(session, 'all', manifest['mutants']['all'][0])
        assert source.read_text() == 'ANCHOR'
        return tally['results'][0]

class ExpectedMoverTests(unittest.TestCase):
    def test_neighbor_does_not_witness_expected(self):
        row = measure([], ['neighbor'], 'expected')
        self.assertEqual(row['verdict'], 'survived')
        self.assertEqual(row['moved'], 1)
        self.assertIn('expected', row['how'])
        self.assertIn('neighbor', row['how'])

    def test_expected_both_neither_and_reverse(self):
        for before, after, verdict in [([], ['expected'], 'killed'),
                ([], ['expected', 'neighbor'], 'killed'), ([], [], 'survived'),
                (['expected'], [], 'killed'),
                (['expected'], ['expected', 'neighbor'], 'survived')]:
            with self.subTest(before=before, after=after):
                self.assertEqual(measure(before, after, 'expected')['verdict'], verdict)

    def test_undeclared_row_is_byte_compatible(self):
        expected = dict(group='all', label='rule', verdict='killed',
                        scope='declared', moved=1, how='1 vector(s) moved')
        self.assertEqual(json.dumps(measure([], ['neighbor']), sort_keys=True),
                         json.dumps(expected, sort_keys=True))

    def test_termination_and_unproved_are_preserved(self):
        for kind, verdict in [('timeout', 'killed'), ('parse-error', 'unproved')]:
            with self.subTest(kind=kind):
                self.assertEqual(measure([], [], 'expected', {'<batch>': kind})
                                 ['verdict'], verdict)

class ExpectedMoverValidationTests(unittest.TestCase):
    def load(self, root, runner='batch', parse='test-names', value='expected', control=False):
        (root / 'source.txt').write_text('ANCHOR')
        mutant = dict(label='rule', anchor='ANCHOR', replacement='CHANGED',
                      expected_mover=value, control=control)
        manifest = dict(schema=ca.SCHEMA, runner=runner, vectors='vectors.json',
                        implementation='source.txt', build=[], outcome_from=['result'],
                        entrypoint_command=['NEVER-EXECUTE'], accepted_exit_codes=[0, 101], mutants={'all': [mutant]})
        if parse is not None:
            manifest['outcome_parse'] = parse
        return ca.load_manifest_bytes(json.dumps(manifest).encode(), root / 'manifest.json')

    def test_valid_batch_name_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = self.load(Path(tmp))
            self.assertEqual(m['mutants']['all'][0]['expected_mover'], 'expected')

    def test_unobservable_modes_refuse_expected_mover(self):
        with tempfile.TemporaryDirectory() as tmp:
            for runner, parse in [('module', None), ('process', None), ('batch', None)]:
                with self.subTest(runner=runner):
                    with self.assertRaisesRegex(ca.ManifestError, 'expected_mover'):
                        self.load(Path(tmp), runner, parse)

    def test_controls_refuse_expected_mover(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ca.ManifestError, 'expected_mover'):
                self.load(Path(tmp), control=True)

    def test_invalid_names_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            for value in ['', ' ', None, False, 1, [], {}]:
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ca.ManifestError, 'expected_mover'):
                        self.load(Path(tmp), value=value)

if __name__ == '__main__':
    unittest.main()
