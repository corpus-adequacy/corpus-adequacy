"""Real filesystem loader tests only; no receipt/CLI/runtime claim."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'measurements'))
import suggestion_evidence as ev
import suggestion_readback as reader
from test_owned_suggestion_assessment import context_fixture


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class Loaders(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.basis = self.root / 'basis'
        shutil.copytree(ROOT / 'fixtures/contained-v1-owned/corpus', self.basis)
        self.expected = self.root / 'expected.json'
        self.expected.write_bytes(context_fixture()[0].expected_raw)

    def test_authentic_factory_tree_outside_checkout_accepts(self):
        snapshot = reader.load_assessment_basis(self.basis)
        self.assertEqual(tuple(p for p, _ in snapshot), ev.BASIS_PATHS)
        self.assertTrue(all(type(raw) is bytes for _, raw in snapshot))
        self.assertEqual(ev.require_basis(snapshot)['allow.json'], b'{"value":5}\n')
        with self.assertRaises(ev.EvidenceError):
            reader.load_assessment_basis(self.basis / 'vectors')
        self.assertEqual(reader.load_expected(self.expected), self.expected.read_bytes())

    def test_same_shape_changed_original_is_not_its_own_oracle(self):
        (self.basis / 'LICENSE').write_bytes(b'changed license')
        with self.assertRaises(ev.EvidenceError) as caught:
            reader.load_assessment_basis(self.basis)
        self.assertEqual(caught.exception.code, 'corpus-derivation')

    def test_missing_surplus_and_case_collision_refuse(self):
        for relative in ('extra', 'vectors/EXTRA', 'vectors/ALLOW.json'):
            p = self.basis / relative
            if p.exists():
                continue  # Case-insensitive filesystems cannot construct this collision.
            p.write_bytes(b'x')
            with self.subTest(path=relative), self.assertRaises(ev.EvidenceError):
                reader.load_assessment_basis(self.basis)
            p.unlink()
        (self.basis / 'LICENSE').unlink()
        with self.assertRaises(ev.EvidenceError):
            reader.load_assessment_basis(self.basis)

    def test_symlink_and_hardlink_inputs_refuse(self):
        license_path = self.basis / 'LICENSE'
        original = license_path.read_bytes()
        external = self.root / 'external'; external.write_bytes(original)
        for create in (lambda: license_path.symlink_to(external),
                       lambda: os.link(external, license_path)):
            license_path.unlink(); create()
            with self.assertRaises(ev.EvidenceError):
                reader.load_assessment_basis(self.basis)
            license_path.unlink(); license_path.write_bytes(original)
        linked_root = self.root / 'linked'; linked_root.symlink_to(self.basis, target_is_directory=True)
        with self.assertRaises(ev.EvidenceError):
            reader.load_assessment_basis(linked_root)
        linked_expected = self.root / 'linked.json'; linked_expected.symlink_to(self.expected)
        with self.assertRaises(ev.EvidenceError):
            reader.load_expected(linked_expected)

    def test_fifo_and_directory_in_file_slot_refuse_without_read(self):
        p = self.basis / 'LICENSE'; p.unlink()
        p.mkdir()
        with self.assertRaises(ev.EvidenceError):
            reader.load_assessment_basis(self.basis)
        p.rmdir(); os.mkfifo(p)
        with mock.patch.object(reader.os, 'read', side_effect=AssertionError('must not read FIFO')):
            with self.assertRaises(ev.EvidenceError):
                reader.load_assessment_basis(self.basis)

    def test_cap_before_json_and_aggregate_budget(self):
        self.expected.write_bytes(b' ' * 65537)
        with mock.patch.object(reader.ev, 'require_expected', side_effect=AssertionError('parse must not run')):
            with self.assertRaises(ev.EvidenceError) as caught:
                reader.load_expected(self.expected)
        self.assertEqual(caught.exception.code, 'member-bytes')
        with mock.patch.object(reader, 'BASIS_TOTAL_BYTES', 1):
            with self.assertRaises(ev.EvidenceError) as caught:
                reader.load_assessment_basis(self.basis)
        self.assertEqual(caught.exception.code, 'aggregate-bytes')

    def test_directory_inventory_stops_at_first_surplus_entry(self):
        class Entries:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def __iter__(self): return self
            count = 0
            def __next__(self):
                self.count += 1
                if self.count > 3:
                    raise AssertionError('unbounded directory enumeration')
                return type('Entry', (), {'name': 'extra'+str(self.count)})()
        entries = Entries()
        with mock.patch.object(reader.os, 'scandir', return_value=entries) as scan:
            with self.assertRaises(ev.EvidenceError):
                reader._inventory(-1, ('LICENSE', 'vectors'))
        scan.assert_called_once_with(-1)
        self.assertEqual(entries.count, 3)

    def test_growing_file_is_stopped_by_stream_cap_before_parse(self):
        original_read = os.read
        grew = False
        def grow(fd, count):
            nonlocal grew
            raw = original_read(fd, count)
            if not grew:
                grew = True
                with self.expected.open('ab') as stream:
                    stream.write(b' ' * 65536)
            return raw
        with mock.patch.object(reader.os, 'read', side_effect=grow), \
                mock.patch.object(reader.ev, 'require_expected', side_effect=AssertionError('parse must not run')):
            with self.assertRaises(ev.EvidenceError) as caught:
                reader.load_expected(self.expected)
        self.assertEqual(caught.exception.code, 'member-bytes')

    def test_duplicate_json_is_not_an_external_expectation(self):
        self.expected.write_bytes(b'{"x":1,"x":2}\n')
        with self.assertRaises(ev.EvidenceError) as caught:
            reader.load_expected(self.expected)
        self.assertEqual(caught.exception.code, 'duplicate-key')

    def test_open_file_replacement_during_read_refuses(self):
        original_read = os.read
        replaced = False
        def replace(fd, count):
            nonlocal replaced
            raw = original_read(fd, count)
            if not replaced:
                replaced = True
                backup = self.root / 'replacement'
                backup.write_bytes(self.expected.read_bytes())
                os.replace(backup, self.expected)
            return raw
        with mock.patch.object(reader.os, 'read', side_effect=replace):
            with self.assertRaises(ev.EvidenceError):
                reader.load_expected(self.expected)

    def test_child_directory_substitution_cannot_escape_open_root(self):
        original_read = os.read
        replaced = False
        external = self.root / 'outside'
        shutil.copytree(self.basis / 'vectors', external)
        def replace(fd, count):
            nonlocal replaced
            raw = original_read(fd, count)
            if not replaced:
                replaced = True
                (self.basis / 'vectors').rename(self.root / 'saved-vectors')
                (self.basis / 'vectors').symlink_to(external, target_is_directory=True)
            return raw
        with mock.patch.object(reader.os, 'read', side_effect=replace):
            with self.assertRaises(ev.EvidenceError):
                reader.load_assessment_basis(self.basis)


class UnsupportedFilesystem(unittest.TestCase):
    def test_missing_descriptor_support_refuses_before_path_open(self):
        with mock.patch.object(reader.os, 'supports_dir_fd', set()):
            for loader in (reader.load_assessment_basis, reader.load_expected):
                with self.subTest(loader=loader.__name__):
                    with self.assertRaises(ev.EvidenceError) as caught:
                        loader('/path-that-must-not-be-opened')
                    self.assertEqual(caught.exception.code, 'unsupported-filesystem')


if __name__ == '__main__':
    unittest.main()
