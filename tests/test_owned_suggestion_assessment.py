"""Admission type/dispatch tests. No production caller is wired by this slice."""
import dataclasses
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'measurements'))
import sealed_measurement_contract as contracts
import suggestion_evidence as ev
from test_suggestion_evidence import prepared_inputs


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
        context, _ = context_fixture()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context.expected_raw = b'changed'
        for raw in (b'', bytearray(b'{}'), {}, b'x'*65537):
            for field in ('expected_raw', 'prepare_raw', 'parent_authorization_raw',
                          'variant_authorization_raw'):
                with self.subTest(field=field, raw_type=type(raw)), self.assertRaises(ValueError):
                    dataclasses.replace(context, **{field: raw})

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


def context_fixture():
    inputs = prepared_inputs()
    members = dict(inputs.retained_members); plan = ev.decode(members['plan.json'])
    plan_hash = ev.digest(members['plan.json']); variant = plan['variants'][0]
    expected = {'schema': ev.PREFIX+'expected.v0', 'plan_sha256': plan_hash,
        'source_content_sha256': plan['source']['content_sha256'],
        'reference_sha256': plan['reference']['sha256'], 'policy': ev.POLICY,
        'receipt_sha256': None, 'source_files': plan['source']['files'], 'reference_approval': 'accept'}
    historical = json.loads((ROOT/'measurements/owned-slice-b-20f6d8b/declared/prepare.v2.json').read_bytes())
    runtime = {k: historical[k] for k in ('toolchain','image','candidate_profile','probe_evidence',
        'network','runtime','oci','ceilings','materialize_ceilings')}
    import hashlib
    config = (ROOT/'execution/aee-checker-sealed/cargo-config.toml').read_bytes()
    tool_hash = hashlib.sha256(b'cargo-config.toml\0'+str(len(config)).encode()+b'\0'+config).hexdigest()
    prepare = {'schema': ev.PREFIX+'prepare.v0','family':ev.FAMILY,'plan_sha256':plan_hash,
        'variant':'base','profile':ev.PROFILE,'source':plan['source'],'pins_sha256':'a'*64,
        'materialized':{'subject_tree_sha256':plan['subject_tree_sha256'],
            'corpus_tree_sha256':variant['tree_sha256'],'corpus_manifest_sha256':variant['manifest']['sha256'],
            'corpus_id_count':5,'vendor_sha256':ev.digest(b''),'tool_sha256':tool_hash},'runtime':runtime}
    prepare_raw=ev.encode(prepare)
    parent={'schema':ev.PREFIX+'authorization.v0','plan_sha256':plan_hash,
        'source_content_sha256':plan['source']['content_sha256'],'profile':ev.PROFILE,
        'prepares':[{'variant':'base','sha256':ev.digest(prepare_raw)},
                    {'variant':'outer-whitespace','sha256':'e'*64}],
        'reference_sha256':plan['reference']['sha256'],'operator':'fixture-only','decision':'execute'}
    parent_raw=ev.encode(parent)
    auth={'schema':ev.PREFIX+'variant-authorization.v0','parent_authorization_sha256':ev.digest(parent_raw),
        'plan_sha256':plan_hash,'variant':'base','prepare_sha256':ev.digest(prepare_raw),
        'profile':ev.PROFILE,'source_content_sha256':plan['source']['content_sha256']}
    context=contracts.OwnedAssessmentAdmissionContext(ev.FAMILY,ev.PROFILE,'base',inputs,
        ev.encode(expected),prepare_raw,parent_raw,ev.encode(auth))
    contract=contracts.OwnedAssessmentVariantContract(plan_hash,'base',variant['manifest']['sha256'],
        variant['tree_sha256'],('allow','boundary','negative','over-limit','proposal'))
    return context,contract


class ContextAdmission(unittest.TestCase):
    def test_actual_context_revalidation_positive_and_detached(self):
        context,contract=context_fixture()
        result=ev.require_assessment_context(context,ev.PROFILE,contract)
        self.assertEqual(result['variant'],'base')
        result['variant']='changed'
        self.assertEqual(ev.require_assessment_context(context,ev.PROFILE,contract)['variant'],'base')

    def test_runtime_checks_match_pinned_source_validators(self):
        import aee_checker_sealed_run as legacy_run
        import aee_checker_sealed_oci as legacy_oci
        import aee_checker_sealed_materialize as legacy_materialize
        context,_=context_fixture(); runtime=ev.decode(context.prepare_raw)['runtime']
        self.assertEqual(ev.require_runtime_preparation(runtime),runtime)
        legacy_run._require_prepare_image({'image':runtime['image']})
        legacy_materialize.require_vendor_toolchain(runtime['toolchain'])
        legacy_oci.require_probe_evidence(runtime['probe_evidence'])
        for name in ('CANDIDATE_RESOURCE_PROFILE_V2','NETWORK_CUTOFF','OCI_CONTRACT',
                     'DECLARED_CEILINGS','MATERIALIZE_CEILINGS'):
            self.assertEqual(ev.encode(getattr(ev,'_'+name)),ev.encode(getattr(legacy_run,name)))
        for mutation in (lambda d:d['candidate_profile'].update(pids=True),
                         lambda d:d['network'].update(sealed_oci='host'),
                         lambda d:d['image'].update(id=d['toolchain']['image_id']),
                         lambda d:d['probe_evidence'][0].update(refusal='completed'),
                         lambda d:d['toolchain'].update(index='other')):
            changed=copy.deepcopy(runtime);mutation(changed)
            with self.subTest(mutation=mutation),self.assertRaises(ev.EvidenceError):
                ev.require_runtime_preparation(changed)

    def test_aggregate_match_does_not_cover_changed_source_file_hash(self):
        context,contract=context_fixture(); doc=ev.decode(context.expected_raw)
        doc['source_files'][0]['sha256']='d'*64
        with self.assertRaises(ev.EvidenceError):
            ev.require_assessment_context(dataclasses.replace(context,expected_raw=ev.encode(doc)),ev.PROFILE,contract)

    def test_matching_hash_does_not_grant_approval(self):
        context,contract=context_fixture()
        for approval in ('unavailable','reject'):
            doc=ev.decode(context.expected_raw);doc['reference_approval']=approval
            changed=dataclasses.replace(context,expected_raw=ev.encode(doc))
            with self.subTest(approval=approval),self.assertRaises(ev.EvidenceError):
                ev.require_assessment_context(changed,ev.PROFILE,contract)

    def test_crossed_and_forged_context_never_reaches_continuation(self):
        context,contract=context_fixture()
        for field,key,value in (
                ('expected_raw','plan_sha256','f'*64),
                ('prepare_raw','family','legacy'),
                ('parent_authorization_raw','decision','unexpected'),
                ('variant_authorization_raw','variant','outer-whitespace')):
            doc=ev.decode(getattr(context,field));doc[key]=value
            forged=copy.copy(context);object.__setattr__(forged,field,ev.encode(doc))
            called=[]
            with self.subTest(field=field),self.assertRaises(ev.EvidenceError):
                ev.require_assessment_context(forged,ev.PROFILE,contract)
                called.append(True)
            self.assertEqual(called,[])


if __name__ == '__main__':
    unittest.main()
