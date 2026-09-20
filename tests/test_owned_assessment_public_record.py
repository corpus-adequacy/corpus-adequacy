"""Replay retained local evidence offline; never execute the candidate."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'measurements'))
import suggestion_readback as reader

RECORD = ROOT / 'measurements/owned-assessment-8c4034c-20260920'
BASIS = ROOT / 'fixtures/contained-v1-owned/corpus'


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class PublicRecord(unittest.TestCase):
    def test_retained_handoff_replays_without_authenticating_origin(self):
        result, code = reader.verify_package(RECORD / 'package', BASIS,
                                              expected=RECORD / 'expected.json')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['expected_identity'], 'match')
        self.assertEqual(result['internal_consistency'], 'match')
        self.assertEqual(result['replay_disposition'], 'eligible-for-human-corpus-PR')
        self.assertEqual(result['origin'], 'unverified')
        self.assertEqual(result['reasons'], [])

    def test_missing_observation_cannot_replay_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp).resolve() / 'package'
            shutil.copytree(RECORD / 'package', target)
            (target / 'base/observations/3.json').unlink()
            result, code = reader.verify_package(target, BASIS, expected=RECORD / 'expected.json')
            self.assertNotEqual(code, 0, result)
            self.assertNotEqual(result['internal_consistency'], 'match')

    def test_changed_review_cannot_inherit_historical_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp).resolve() / 'package'
            shutil.copytree(RECORD / 'package', target)
            path = target / 'review.json'
            review = json.loads(path.read_bytes())
            review['rationale'] = 'Changed after review'
            path.write_text(json.dumps(review, sort_keys=True, separators=(',', ':')) + '\n')
            result, code = reader.verify_package(target, BASIS, expected=RECORD / 'expected.json')
            self.assertNotEqual(code, 0, result)
            self.assertNotEqual(result['internal_consistency'], 'match')

    def test_foreign_receipt_expectation_refuses_even_consistent_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'expected.json'
            expected = json.loads((RECORD / 'expected.json').read_bytes())
            expected['receipt_sha256'] = 'a' * 64
            path.write_text(json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n')
            result, code = reader.verify_package(RECORD / 'package', BASIS, expected=path)
            self.assertEqual(code, 1, result)
            self.assertEqual(result['expected_identity'], 'mismatch')
