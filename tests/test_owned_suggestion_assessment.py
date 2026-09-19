"""Admission type/dispatch tests. No production caller is wired by this slice."""
import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'measurements'))
import sealed_measurement_contract as contracts
import suggestion_evidence as ev


class AdmissionTypes(unittest.TestCase):
    def test_variant_is_distinct_and_frozen(self):
        value = contracts.OwnedAssessmentVariantContract(
            plan_sha256='a'*64, variant='base', corpus_manifest_sha256='b'*64,
            corpus_tree_sha256='c'*64,
            ids=('allow', 'boundary', 'negative', 'over-limit', 'proposal'))
        self.assertNotIsInstance(value, contracts.SealedMeasurementContract)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.variant = 'outer-whitespace'
        for kwargs in ({'variant': 'unknown'}, {'ids': ('x',)*5},
                       {'plan_sha256': 'not-a-digest'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                dataclasses.replace(value, **kwargs)

    def test_context_is_an_immutable_carrier_with_bounded_bytes(self):
        contract = contracts.OwnedAssessmentVariantContract(
            'a'*64, 'base', 'b'*64, 'c'*64,
            ('allow', 'boundary', 'negative', 'over-limit', 'proposal'))
        context = contracts.OwnedAssessmentAdmissionContext(
            ev.FAMILY, ev.PROFILE, 'base', b'{}', b'{}', b'{}', b'{}',
            'a'*64, 'b'*64, 'c'*64, contract)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context.plan_raw = b'changed'
        for raw in (b'', bytearray(b'{}'), {}, b'x'*65537):
            for field in ('plan_raw', 'prepare_raw', 'parent_authorization_raw',
                          'variant_authorization_raw'):
                with self.subTest(field=field, raw_type=type(raw)), self.assertRaises(ValueError):
                    dataclasses.replace(context, **{field: raw})
        for changes in ({'family': 'legacy'}, {'profile': 'contained-oci-v0'},
                        {'variant': 'unknown'}, {'expected_plan_sha256': 'bad'},
                        {'variant_contract': object()}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                dataclasses.replace(context, **changes)

    def test_dispatch_is_closed_and_requires_no_backend(self):
        self.assertEqual(ev.require_assessment_dispatch(
            'owned-suggestion-assessment-v0', 'contained-oci-v1',
            ev.PREFIX+'prepare.v0'), ev.PREFIX+'prepare.v0')
        for family, profile, schema in (
            ('legacy-sealed', 'contained-oci-v1', ev.PREFIX+'prepare.v0'),
            ('owned-suggestion-assessment-v0', 'contained-oci-v0', ev.PREFIX+'prepare.v0'),
            ('owned-suggestion-assessment-v0', 'contained-oci-v1',
             'corpus-adequacy.aee-checker-sealed.prepare.v2'),
            ('unknown', 'contained-oci-v1', ev.PREFIX+'prepare.v0')):
            with self.subTest(family=family, profile=profile, schema=schema):
                with self.assertRaises(ev.EvidenceError):
                    ev.require_assessment_dispatch(family, profile, schema)


if __name__ == '__main__':
    unittest.main()
