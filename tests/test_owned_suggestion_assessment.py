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
from test_suggestion_evidence import prepared_inputs, structural_members


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
    evidence = structural_members(inputs)
    inputs = dataclasses.replace(inputs, evidence_members=tuple(sorted(evidence.items())))
    prepare_raw = evidence['base/prepare.json']
    parent_raw = evidence['authorization.json']
    auth = ev.decode(evidence['base/authorization.json'])
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


class ProducerCLI(unittest.TestCase):
    def run_cli(self, *args):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            p = subprocess.run([sys.executable, str(ROOT/'measurements/owned_suggestion_assessment.py'), *args],
                cwd=cwd, stdout=stdout, stderr=stderr, timeout=5)
            stdout.seek(0); raw=stdout.read(65537)
            stderr.seek(0); err=stderr.read(65537)
        self.assertLessEqual(len(raw),65536);self.assertLessEqual(len(err),65536)
        return p.returncode,raw,err

    def test_producer_unknown_command_is_closed(self):
        code,raw,err=self.run_cli('not-a-command')
        self.assertEqual(code,2);self.assertEqual(err,b'')
        self.assertEqual(ev.decode(raw,canonical=True),{
            'schema':ev.PREFIX+'command-result.v0','command':'invalid','status':'refused','artifacts':[],
            'reasons':[{'stage':'input','code':'argument-invalid','member':None}]})

    def test_all_commands_require_explicit_inputs(self):
        for command in ('plan','prepare','authorize','execute','finalize'):
            code,raw,err=self.run_cli(command)
            self.assertEqual((code,err),(2,b''))
            doc=ev.decode(raw,canonical=True)
            self.assertEqual(doc['command'],command)
            self.assertEqual(doc['reasons'][0]['code'],'argument-invalid')


def producer_workspace(test):
    """Committed synthetic source identity, real installed bytes; never live approval."""
    import os, subprocess, tempfile
    folder=tempfile.TemporaryDirectory();test.addCleanup(folder.cleanup)
    base=Path(folder.name).resolve();source=base/'source';source.mkdir()
    def git(*args):
        run=subprocess.run(['git','-C',str(source),*args],capture_output=True,timeout=5,
            env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null'))
        test.assertEqual(run.returncode,0,run.stderr)
        return run.stdout.decode().strip()
    git('init','-q')
    total=0
    for name in ev.SOURCE_PATHS:
        raw=(ROOT/name).read_bytes();total+=len(raw)
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    for name in ('control.json','sites.json'):
        path=source/'measurements/owned-independent-v0'/name
        path.write_bytes((ROOT/'measurements/owned-independent-v0'/name).read_bytes())
    test.assertLess(total,4*1024*1024)
    git('add','--','.')
    git('-c','user.name=Synthetic test','-c','user.email=synthetic@example.invalid','commit','-qm','synthetic source fixture')
    inputs=prepared_inputs();members=dict(inputs.retained_members)
    basis=base/'basis';basis.mkdir()
    for name,raw in inputs.basis_members:
        path=basis/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    for name in ('proposal.json','reference.json'):(base/name).write_bytes(members[name])
    return base,source,basis,git


class ProducerSourceIdentity(unittest.TestCase):
    def test_real_source_measurement_and_dirty_missing_untracked_refusals(self):
        import aee_checker_sealed_run as run
        base,source,basis,git=producer_workspace(self)
        self.assertTrue(hasattr(run,'assessment_execution_identity'))
        identity=run.assessment_execution_identity(source)
        self.assertEqual(identity['commit'],git('rev-parse','HEAD'))
        self.assertEqual([row['path'] for row in identity['files']],list(ev.SOURCE_PATHS))
        import hashlib
        digest=hashlib.sha256()
        for name in ev.SOURCE_PATHS:
            raw=(source/name).read_bytes();digest.update(name.encode()+b'\0'+str(len(raw)).encode()+b'\0'+raw)
        self.assertEqual(identity['content_sha256'],digest.hexdigest())
        target=source/'measurements/owned_suggestion_assessment.py';raw=target.read_bytes()
        target.write_bytes(raw+b'\n# dirty\n')
        with self.assertRaises(ev.EvidenceError):run.assessment_execution_identity(source)
        target.unlink()
        with self.assertRaises(ev.EvidenceError):run.assessment_execution_identity(source)
        target.write_bytes(raw)
        import subprocess
        untracked=base/'untracked';untracked.mkdir()
        subprocess.run(['git','-C',str(untracked),'init','-q'],check=True,capture_output=True,timeout=5)
        p=untracked/'measurements/owned_suggestion_assessment.py';p.parent.mkdir();p.write_bytes(raw)
        with self.assertRaises(ev.EvidenceError):run.assessment_execution_identity(untracked)


class ProducerPlan(ProducerCLI):
    def test_actual_plan_cli_preserves_basis_and_derives_both_corpora(self):
        base,source,basis,git=producer_workspace(self)
        before=reader_basis=__import__('suggestion_readback').load_assessment_basis(basis)
        dest=base/'plan'
        args=['plan','--proposal',str(base/'proposal.json'),'--reference',str(base/'reference.json'),
              '--reference-sha256',ev.digest((base/'reference.json').read_bytes()),'--reference-approval','accept',
              '--root',str(source),'--basis-dir',str(basis),'--out',str(dest)]
        code,raw,err=self.run_cli(*args)
        self.assertEqual((code,err),(0,b''),raw)
        result=ev.decode(raw,canonical=True)
        self.assertEqual(result['artifacts'],[{'kind':'plan','sha256':ev.digest((dest/'plan.json').read_bytes())}])
        members=__import__('suggestion_readback').load_package(dest)
        retained=tuple((p,b) for p,b in members if p in ('plan.json','proposal.json','reference.json') or '/corpus/' in p)
        gates,values=ev.evaluate_preflight(ev.AssessmentInputs(retained,reader_basis))
        self.assertEqual([g['status'] for g in gates],['passed']*3)
        self.assertEqual(values['plan']['source']['commit'],git('rev-parse','HEAD'))
        self.assertEqual(__import__('suggestion_readback').load_assessment_basis(basis),before)
        code,raw,err=self.run_cli(*args)
        self.assertEqual(code,2);self.assertEqual(ev.decode(raw)['artifacts'],[])

    def test_rejected_reference_never_publishes_a_plan(self):
        base,source,basis,git=producer_workspace(self)
        for approval,reason in (('reject','reference-rejected'),('unavailable','reference-required')):
            dest=base/approval
            code,raw,err=self.run_cli('plan','--proposal',str(base/'proposal.json'),
                '--reference',str(base/'reference.json'),'--reference-sha256',ev.digest((base/'reference.json').read_bytes()),
                '--reference-approval',approval,'--root',str(source),'--basis-dir',str(basis),'--out',str(dest))
            self.assertEqual(code,2);self.assertEqual(ev.decode(raw)['reasons'][0]['code'],reason)
            self.assertFalse(dest.exists())
