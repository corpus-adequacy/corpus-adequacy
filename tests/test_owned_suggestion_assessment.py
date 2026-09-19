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


def context_fixture(inputs=None):
    inputs = prepared_inputs() if inputs is None else inputs
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


class DerivedContractConsumers(unittest.TestCase):
    def test_fixed_owned_projections_and_dynamic_adapter_ids(self):
        import aee_checker_sealed_candidate as candidate
        context, contract = context_fixture()
        self.assertEqual(contract.candidate_build, contracts.OWNED_INDEPENDENT_V0_CONTRACT.candidate_build)
        self.assertEqual(contract.site_ids, ('upper-guard-first-overflow-only',))
        self.assertEqual(contract.corpus_id_count, 5)
        self.assertEqual(candidate.sealed_adapter_for(contract).__name__, 'owned_contained_v1')
        with self.assertRaises(dataclasses.FrozenInstanceError):
            contract.ids = ('changed',)


class FourConsumerAdmission(unittest.TestCase):
    def invoke(self, name, context, selected_contract, **changes):
        import aee_checker_sealed_candidate as candidate
        import aee_checker_sealed_runtime as runtime
        import aee_checker_sealed_execute as funnel
        import aee_checker_sealed_driver as driver
        import envelope_collection as collection
        kwargs = dict(prepare_raw=context.prepare_raw, execution_profile=ev.PROFILE,
                      contract=selected_contract, assessment_context=context)
        if name == 'candidate':
            kwargs.update(mounts={}, binding=candidate.envelope_binding(
                prepare_sha256=ev.digest(context.prepare_raw),
                execution_commit=ev.decode(context.prepare_raw)['source']['commit']))
            function = candidate.run_sealed_candidate
        elif name == 'runtime':
            kwargs.update(materialized={key: Path('/nonexistent')/key for key in ('corpus','vendor','tool')},
                          envelope_sink=lambda record: None, ledger=collection.Ledger())
            function = runtime.make_sealed_backend
        elif name == 'funnel':
            kwargs.update(authorize_raw=context.variant_authorization_raw,
                          pins_dir=ROOT/'measurements/owned-independent-v0',
                          manifest=json.loads((ROOT/'measurements/owned-independent-v0/manifest.json').read_bytes()),
                          manifest_path=ROOT/'measurements/owned-independent-v0/manifest.json',
                          execution_backend=lambda *a, **k: None)
            function = funnel.run_execution_funnel
        else:
            kwargs.update(authorize_raw=context.variant_authorization_raw,
                          pins_dir=ROOT/'measurements/owned-independent-v0',
                          materialize_dest=Path('/nonexistent'), root=ROOT)
            function = driver.run_authorized
        kwargs.update(changes)
        return function(**kwargs)

    def test_all_four_refuse_crossing_before_effects(self):
        from unittest import mock
        import aee_checker_sealed_candidate as candidate
        import aee_checker_sealed_driver as driver
        import corpus_adequacy as ca
        context, contract = context_fixture()
        expected = ev.decode(context.expected_raw); expected['reference_approval']='reject'
        cases = [dict(assessment_context=None), dict(contract=contracts.OWNED_INDEPENDENT_V0_CONTRACT),
                 dict(prepare_raw=context.prepare_raw+b' '),
                 dict(assessment_context=dataclasses.replace(context,expected_raw=ev.encode(expected))),
                 dict(execution_profile='contained-oci-v0')]
        with mock.patch.object(candidate,'_run_sealed_candidate',side_effect=AssertionError('transport')) as run, \
             mock.patch.object(driver,'materialize_pinned',side_effect=AssertionError('network')) as mat, \
             mock.patch.object(ca,'_run_process',side_effect=AssertionError('engine')) as engine:
            for name in ('candidate','runtime','funnel','driver'):
                for changes in cases:
                    with self.subTest(consumer=name,changes=tuple(changes)), self.assertRaises(ev.EvidenceError):
                        self.invoke(name,context,contract,**changes)
            self.assertEqual((run.call_count,mat.call_count,engine.call_count),(0,0,0))

    def test_candidate_admits_context_and_checks_binding(self):
        from unittest import mock
        import aee_checker_sealed_candidate as candidate
        context, contract=context_fixture()
        with mock.patch.object(candidate,'_run_sealed_candidate',return_value='terminal synthetic transport') as run:
            self.assertEqual(self.invoke('candidate',context,contract),'terminal synthetic transport')
            self.assertEqual(run.call_args.kwargs['image_id'],ev.decode(context.prepare_raw)['runtime']['toolchain']['image_id'])
            with self.assertRaises(ev.EvidenceError):
                self.invoke('candidate',context,contract,binding={'prepare_sha256':'f'*64,'execution_commit':'a'*40})
            self.assertEqual(run.call_count,1)

    def test_funnel_uses_real_order_binder_and_combined_engine(self):
        from unittest import mock
        import corpus_adequacy as ca
        context,contract=context_fixture()
        with mock.patch.object(ca,'_run_process',return_value={'synthetic':True}) as engine:
            self.assertEqual(self.invoke('funnel',context,contract),{'synthetic':True})
            call=engine.call_args.kwargs
            self.assertIs(call['separate_build_phase'],False)
            self.assertEqual(len(call['mutation_order']),3)
            self.assertIn('CONTROL',call['mutation_order'][0])
            with self.assertRaises(ev.EvidenceError):
                self.invoke('funnel',context,contract,authorize_raw=context.parent_authorization_raw)
            self.assertEqual(engine.call_count,1)

    def test_runtime_admission_is_not_conditional_on_sink(self):
        context,contract=context_fixture()
        with self.assertRaises(ev.EvidenceError):
            self.invoke('runtime',context,contract,envelope_sink=None)
        with self.assertRaises(ev.EvidenceError):
            self.invoke('runtime',context,contract,ledger=None)
        self.assertTrue(callable(self.invoke('runtime',context,contract)))


class OfflinePreparation(unittest.TestCase):
    def inputs(self):
        import tempfile, tarfile
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        inputs=root/'inputs';inputs.mkdir();(inputs/'vendor').mkdir()
        with tarfile.open(inputs/'subject.tar.gz','w:gz') as archive:
            archive.add(ROOT/'fixtures/contained-v1-owned/candidate',arcname='repo/fixtures/contained-v1-owned/candidate')
        context,_=context_fixture()
        tc=ev.decode(context.prepare_raw)['runtime']['toolchain']
        (inputs/'toolchain.json').write_bytes(ev.encode(tc))
        return root, inputs, context, tc

    def materialize(self, root, inputs, context):
        import aee_checker_sealed_materialize as mat
        return mat.materialize_owned_assessment(inputs,root/'out',
            retained_members=context.assessment_inputs.retained_members,variant='base',
            template=ROOT/'execution/aee-checker-sealed/cargo-config.toml')

    def test_actual_archive_and_derived_corpus_with_terminal_host_observation(self):
        from unittest import mock
        import aee_checker_sealed_materialize as mat
        root,inputs,context,tc=self.inputs()
        inspect=json.dumps([{'Id':tc['image_id'],'Os':'linux','Architecture':tc['platform'].split('/')[1]}]).encode()
        with mock.patch.object(mat,'docker_bounded',return_value=inspect) as host, \
             mock.patch.object(mat,'_observe_image_cmd',side_effect=[tc['rustc_Vv'],tc['cargo_V']+'\n']) as observe, \
             mock.patch.object(mat,'materialize_pinned',side_effect=AssertionError('network')):
            got=self.materialize(root,inputs,context)
        want=ev.decode(context.prepare_raw)['materialized']
        for key,value in want.items():self.assertEqual(got[key],value,key)
        self.assertEqual(host.call_args.args[0],['image','inspect',tc['image_id']])
        self.assertEqual(observe.call_count,2)
        self.assertEqual((root/'out/corpus/vectors/proposal.json').read_bytes(),dict(context.assessment_inputs.retained_members)['base/corpus/proposal.json'])

    def test_wrong_materialized_filename_and_forged_hash_refuse(self):
        from unittest import mock
        import aee_checker_sealed_materialize as mat
        root,inputs,context,tc=self.inputs()
        inspect=json.dumps([{'Id':tc['image_id'],'Os':'linux','Architecture':tc['platform'].split('/')[1]}]).encode()
        with mock.patch.object(mat,'docker_bounded',return_value=inspect), \
             mock.patch.object(mat,'_observe_image_cmd',side_effect=[tc['rustc_Vv'],tc['cargo_V']+'\n']):
            self.materialize(root,inputs,context)
        (root/'out/prepare.json').write_bytes(context.prepare_raw)
        copied=mat.copy_owned_assessment_preparation(root/'out',root/'copy',context=context)
        self.assertEqual(copied['tool_sha256'],'25a225d61331c075a8bf7c7dddff0767cdf055074aa0da20bdbfed8eee0302e9')
        (root/'out/tool/config.toml').rename(root/'out/tool/cargo-config.toml')
        with self.assertRaises(ev.EvidenceError):
            mat.copy_owned_assessment_preparation(root/'out',root/'wrong',context=context)
        altered=ev.decode(context.prepare_raw)
        altered['materialized']['tool_sha256']='9347dbb76a065d01681b3cb3cae495aad64f5026d5f5b62c90283a0a1e4afa51'
        evidence=dict(context.assessment_inputs.evidence_members)
        prepares={v:evidence[v+'/prepare.json'] for v in ev.VARIANTS};prepares['base']=ev.encode(altered)
        with self.assertRaises(ev.EvidenceError):
            ev.build_assessment_authorization(dataclasses.replace(context.assessment_inputs,evidence_members=()),
                {p:b for p,b in evidence.items() if '/pins/' in p},prepares,context.expected_raw,'fixture')

    def test_bad_inputs_refuse_before_host(self):
        from unittest import mock
        import aee_checker_sealed_materialize as mat
        import aee_checker_sealed_common as common
        for kind in ('surplus','vendor','symlink','bad-toolchain','archive-link'):
            root,inputs,context,tc=self.inputs()
            if kind=='surplus':(inputs/'extra').write_bytes(b'x')
            elif kind=='vendor':(inputs/'vendor/x').write_bytes(b'x')
            elif kind=='symlink':
                (inputs/'toolchain.json').unlink();(inputs/'toolchain.json').symlink_to(root/'missing')
            elif kind=='bad-toolchain':(inputs/'toolchain.json').write_bytes(b'{}\n')
            else:
                import tarfile
                with tarfile.open(inputs/'subject.tar.gz','w:gz') as archive:
                    entry=tarfile.TarInfo('repo/fixtures/contained-v1-owned/candidate/evil');entry.type=tarfile.SYMTYPE;entry.linkname='/tmp/outside';archive.addfile(entry)
            with self.subTest(kind=kind),mock.patch.object(mat,'docker_bounded',side_effect=AssertionError('host before offline admission')) as host:
                with self.assertRaises((ev.EvidenceError,common.PrepareError)):
                    self.materialize(root,inputs,context)
                self.assertEqual(host.call_count,0)


class ProducerAuthorization(unittest.TestCase):
    def test_builds_three_bound_records_and_reuses_structure(self):
        context,_=context_fixture()
        records=dict(context.assessment_inputs.evidence_members)
        inputs=dataclasses.replace(context.assessment_inputs,evidence_members=())
        pins={p:b for p,b in records.items() if '/pins/' in p}
        prepares={v:records[v+'/prepare.json'] for v in ev.VARIANTS}
        output=ev.build_assessment_authorization(inputs,pins,prepares,context.expected_raw,'test operator')
        self.assertEqual(set(output),{'authorization.json','base/authorization.json','outer-whitespace/authorization.json'})
        evidence={**pins,**{v+'/prepare.json':b for v,b in prepares.items()},**output}
        structure=ev.require_assessment_structure(dataclasses.replace(inputs,evidence_members=tuple(sorted(evidence.items()))),require_collections=False)
        self.assertEqual(structure['prepares']['base']['variant'],'base')
        self.assertEqual(ev.decode(output['authorization.json'])['operator'],'test operator')

    def test_crossed_preparation_and_unapproved_expected_refuse(self):
        context,_=context_fixture();records=dict(context.assessment_inputs.evidence_members)
        inputs=dataclasses.replace(context.assessment_inputs,evidence_members=())
        pins={p:b for p,b in records.items() if '/pins/' in p}
        prepares={v:records[v+'/prepare.json'] for v in ev.VARIANTS}
        bad=ev.decode(context.expected_raw);bad['reference_approval']='unavailable'
        for changed,expected in ((dict.fromkeys(ev.VARIANTS,prepares['base']),context.expected_raw),(prepares,ev.encode(bad))):
            with self.assertRaises(ev.EvidenceError):
                ev.build_assessment_authorization(inputs,pins,changed,expected,'test operator')


class ProducerAuthorizationCLI(ProducerCLI):
    def test_cli_authorizes_exact_plan_and_publishes_only_three_records(self):
        import tempfile
        from argparse import Namespace
        import owned_suggestion_assessment as producer
        context,_=context_fixture(); all_p=dict(context.assessment_inputs.evidence_members)
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        basis=root/'basis';basis.mkdir()
        for name,raw in context.assessment_inputs.basis_members:
            path=basis/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        plan=root/'plan'
        producer._publish({**dict(context.assessment_inputs.retained_members),
                           **{p:b for p,b in all_p.items() if '/pins/' in p}},plan)
        for variant in ev.VARIANTS:(root/(variant+'.json')).write_bytes(all_p[variant+'/prepare.json'])
        expected=root/'expected.json';expected.write_bytes(context.expected_raw)
        args=['authorize','--plan-dir',str(plan),'--basis-dir',str(basis),'--expected',str(expected),
              '--base-prepare',str(root/'base.json'),'--whitespace-prepare',str(root/'outer-whitespace.json'),
              '--operator','fixture operator','--out',str(root/'authorized')]
        code,raw,err=self.run_cli(*args)
        self.assertEqual((code,err),(0,b''),raw)
        result=ev.decode(raw,canonical=True);self.assertEqual(len(result['artifacts']),3)
        import suggestion_readback as reader
        self.assertEqual(set(dict(reader.load_package(root/'authorized'))),
                         {'authorization.json','base/authorization.json','outer-whitespace/authorization.json'})
        code,raw,err=self.run_cli(*args)
        self.assertEqual(code,2);self.assertEqual(ev.decode(raw)['artifacts'],[])


class RuntimeCallAdmission(FourConsumerAdmission):
    def test_revalidates_at_call_time_before_subject_or_candidate_effect(self):
        from unittest import mock
        import aee_checker_sealed_runtime as runtime
        import corpus_adequacy as ca
        for corruption in ('profile','context','step'):
            context,contract=context_fixture()
            backend=self.invoke('runtime',context,contract)
            step={'kind':'baseline','group':'independent','id':None}
            if corruption=='profile':setattr(backend,ca.BACKEND_PROFILE_ATTRIBUTE,'contained-oci-v0')
            elif corruption=='context':object.__setattr__(context,'prepare_raw',context.prepare_raw+b' ')
            else:step['kind']='build'
            with self.subTest(corruption=corruption), \
                 mock.patch.object(runtime,'normalize_readonly_bind_modes',side_effect=AssertionError('subject effect')) as normalize, \
                 mock.patch.object(runtime.candidate,'run_sealed_candidate',side_effect=AssertionError('candidate effect')) as candidate:
                with self.assertRaises(ev.EvidenceError):
                    backend({'_repo_root':Path('/missing')},[{'id':'<batch>'}],rebuild=True,step=step)
                self.assertEqual((normalize.call_count,candidate.call_count),(0,0))


class DriverSourceAdmission(FourConsumerAdmission):
    def test_actual_dirty_source_refuses_before_materializer_or_backend(self):
        from unittest import mock
        import aee_checker_sealed_driver as driver
        import aee_checker_sealed_runtime as runtime
        context,contract=context_fixture()
        _,source,_,_=producer_workspace(self)
        target=source/ev.SOURCE_PATHS[0]
        target.write_bytes(target.read_bytes()+b'\n# fixture drift\n')
        # Actual dirty fixture source, never a mocked matching source dictionary.
        with mock.patch.object(driver,'materialize_pinned',side_effect=AssertionError('network')) as old, \
             mock.patch.object(runtime,'make_sealed_backend',side_effect=AssertionError('backend')) as backend:
            with self.assertRaises(ev.EvidenceError) as refusal:
                self.invoke('driver',context,contract,root=source)
            self.assertEqual(refusal.exception.code,'source-identity')
            self.assertEqual((old.call_count,backend.call_count),(0,0))


class PreparationCommand(OfflinePreparation):
    def test_real_prepare_command_binds_source_and_both_local_images(self):
        from unittest import mock
        from argparse import Namespace
        import owned_suggestion_assessment as producer
        import aee_checker_sealed_materialize as mat
        import aee_checker_sealed_run as run
        root,local_inputs,old_context,tc=self.inputs()
        base,source,basis,_=producer_workspace(self)
        identity=run.assessment_execution_identity(source)
        retained=ev.build_assessment_plan((base/'proposal.json').read_bytes(),
            (base/'reference.json').read_bytes(),old_context.assessment_inputs.basis_members,identity)
        plan=ev.decode(dict(retained)['plan.json']);plan_dir=base/'plan'
        producer._publish({**dict(retained),**producer._plan_pins(dict(retained)['plan.json'],source)},plan_dir)
        expected=ev.decode(old_context.expected_raw)
        expected.update(plan_sha256=ev.digest(dict(retained)['plan.json']),source_content_sha256=identity['content_sha256'],
                        source_files=identity['files'])
        expected_path=base/'expected.json';expected_path.write_bytes(ev.encode(expected))
        runtime=ev.decode(old_context.prepare_raw)['runtime']
        args=Namespace(plan_dir=plan_dir,basis_dir=basis,expected=expected_path,variant='base',
                       image_id=runtime['image']['id'],inputs_dir=local_inputs,out=base/'prepared')
        inspect=json.dumps([{'Id':tc['image_id'],'Os':'linux','Architecture':tc['platform'].split('/')[1]}]).encode()
        probe_results=[]
        by_mechanism={row['mechanism']:row for row in runtime['probe_evidence']}
        def probe(**kw):
            probe_results.append(kw)
            if kw['mode']=='network':
                row=by_mechanism['network-off'];side='refusal' if kw['sealed'] else 'control'
            else:
                mechanism,side=next((m,side) for m,pair in run.SEALED_PROBE_PAIRS.items()
                    for side,mode in zip(('control','refusal'),pair) if mode==kw['mode'])
                row=by_mechanism[mechanism]
            return {'state':row[side],'contract':row['inspect'][side]}
        with mock.patch.object(producer,'_HERE',source/'measurements'), \
             mock.patch.object(mat,'docker_bounded',return_value=inspect), \
             mock.patch.object(mat,'_observe_image_cmd',side_effect=[tc['rustc_Vv'],tc['cargo_V']+'\n']), \
             mock.patch.object(run,'require_docker_ready'), \
             mock.patch.object(run,'require_local_image') as local, \
             mock.patch.object(run,'image_platform',return_value=runtime['image']['platform']), \
             mock.patch.object(run,'docker_bounded',return_value=runtime['runtime']['docker'].encode()), \
             mock.patch.object(run,'run_inert_probe',side_effect=probe), \
             mock.patch.object(run,'build_inert_image',side_effect=AssertionError('image build')), \
             mock.patch.object(mat,'materialize_pinned',side_effect=AssertionError('network materializer')):
            result,code=producer.prepare_command(args)
        self.assertEqual(code,0);self.assertEqual(result['command'],'prepare')
        prepared=ev.decode((args.out/'prepare.json').read_bytes(),canonical=True)
        self.assertEqual(prepared['source'],identity)
        self.assertEqual(prepared['runtime'],runtime)
        self.assertEqual(len(probe_results),12)
        local.assert_called_once_with(args.image_id)
        self.assertEqual(set(p.name for p in args.out.iterdir()),{'prepare.json','subject','corpus','vendor','tool'})


class ProducerFinalization(ProducerCLI):
    def test_finalizes_real_staging_frame_without_synthetic_final_records(self):
        import tempfile
        import owned_suggestion_assessment as producer
        import suggestion_readback as reader
        from test_suggestion_readback import package_fixture
        fixture=package_fixture()
        self.assertIsInstance(fixture,tuple)
        members,basis,expected=fixture
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        stage={p:b for p,b in members.items() if p not in ('decision.json','receipt.json','review.json')}
        producer._publish(stage,root/'stage')
        basis_path=root/'basis';basis_path.mkdir()
        for name,raw in basis:
            p=basis_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        expected_path=root/'expected.json';expected_path.write_bytes(ev.encode(expected))
        code,raw,err=self.run_cli('finalize','--assessment-dir',str(root/'stage'),'--pending-review',
            '--out',str(root/'final'),'--expected',str(expected_path),'--basis-dir',str(basis_path))
        self.assertEqual((code,err),(0,b''),raw)
        final=dict(reader.load_package(root/'final'))
        self.assertEqual(final['gates.json'],members['gates.json'])
        self.assertEqual(final['evidence-index.json'],members['evidence-index.json'])
        self.assertEqual(ev.decode(final['decision.json'])['disposition'],'pending-review')
        self.assertEqual(reader.verify_package(root/'final',basis_path,expected=expected_path)[1],0)


class RealDriverEngine(OfflinePreparation):
    def test_real_driver_engine_and_four_mutated_calls(self):
        self._drive()

    def test_actual_control_exception_has_no_returned_engine_control_result(self):
        self._drive(failure_slot=1)

    def _drive(self, failure_slot=None, control_observer=None):
        from unittest import mock
        import subprocess
        import aee_checker_sealed_driver as driver
        import aee_checker_sealed_candidate as candidate
        import aee_checker_sealed_run as run
        import aee_checker_sealed_materialize as mat
        import envelope_collection as collection
        import effective_envelope as envelope
        from test_suggestion_evidence import full_fixture
        base,source,basis,_=producer_workspace(self)
        original=prepared_inputs();raws=dict(original.retained_members)
        retained=ev.build_assessment_plan(raws['proposal.json'],raws['reference.json'],original.basis_members,
            run.assessment_execution_identity(source))
        context,contract=context_fixture(ev.AssessmentInputs(retained,original.basis_members))
        root,local_inputs,_,tc=self.inputs()
        inspect=json.dumps([{'Id':tc['image_id'],'Os':'linux','Architecture':tc['platform'].split('/')[1]}]).encode()
        with mock.patch.object(mat,'docker_bounded',return_value=inspect), \
             mock.patch.object(mat,'_observe_image_cmd',side_effect=[tc['rustc_Vv'],tc['cargo_V']+'\n']):
            materialized=self.materialize(root,local_inputs,context)
        (root/'out/prepare.json').write_bytes(context.prepare_raw)
        evidence=dict(context.assessment_inputs.evidence_members)
        pins=base/'pins';pins.mkdir()
        for path,raw in evidence.items():
            if path.startswith('base/pins/'):(pins/path.split('/')[-1]).write_bytes(raw)
        fixture,wire=full_fixture();reference=wire[0]
        records=dict(fixture.evidence_members)
        actual_sources=[]
        def terminal(**kw):
            ordinal=len(actual_sources)
            if ordinal == failure_slot:
                raise RuntimeError('synthetic terminal interruption')
            actual_sources.append((kw['mounts']['subject']/'src/check.rs').read_text())
            obs=reference[ordinal]
            # Literal synthetic terminal responses, never real candidate execution.
            raw=obs['raw'];stdout=json.dumps({'rows':raw['outcomes']['<batch>'][0],
                'diagnostics':raw['diagnostics']['<batch>'][0]})
            result=subprocess.CompletedProcess([],0,stdout,'')
            record=ev.decode(records['base/envelopes/member-%04d.json'%ordinal])
            record['execution_commit']=kw['binding']['execution_commit']
            record['prepare_sha256']=kw['binding']['prepare_sha256']
            result.envelope_record=record
            return result
        with mock.patch.object(candidate,'_run_sealed_candidate',side_effect=terminal), \
             mock.patch.object(driver,'materialize_pinned',side_effect=AssertionError('network')):
            if failure_slot is not None:
                with self.assertRaisesRegex(RuntimeError,'synthetic terminal interruption'):
                    driver.run_authorized(authorize_raw=context.variant_authorization_raw,
                        prepare_raw=context.prepare_raw,pins_dir=pins,materialize_dest=base/'execution',root=source,
                        execution_profile=ev.PROFILE,assessment_context=context,contract=contract,
                        assessment_prepare_dir=root/'out',envelope_dest=base/'envelopes',
                        **({'assessment_control_observer':control_observer} if control_observer is not None else {}))
                index=ev.decode((base/'envelopes/collection-index.v0.json').read_bytes())
                self.assertEqual([r['state'] for r in index['ledger']],['recorded']*failure_slot+['raised'])
                self.assertEqual(index['attempts'],failure_slot+1)
                return
            report=driver.run_authorized(authorize_raw=context.variant_authorization_raw,
                prepare_raw=context.prepare_raw,pins_dir=pins,materialize_dest=base/'execution',root=source,
                execution_profile=ev.PROFILE,assessment_context=context,contract=contract,
                assessment_prepare_dir=root/'out',envelope_dest=base/'envelopes',
                        **({'assessment_control_observer':control_observer} if control_observer is not None else {}))
        self.assertEqual(len(actual_sources),4)
        self.assertNotIn('return (false, "control-refusal"',actual_sources[0])
        self.assertIn('return (false, "control-refusal"',actual_sources[1])
        self.assertIn('if false',actual_sources[2])
        self.assertIn('maximum.saturating_add(1)',actual_sources[3])
        self.assertEqual(report['control_status'],'killed')
        index=ev.decode((base/'envelopes/collection-index.v0.json').read_bytes())
        self.assertIsNone(index['report_sha256'])
        self.assertEqual(index['attempts'],4)


class ProducerJournal(unittest.TestCase):
    def test_started_is_durable_before_call_and_exact_return_is_retained(self):
        import tempfile
        import owned_suggestion_assessment as producer
        import corpus_adequacy as ca
        import envelope_collection as collection
        from test_suggestion_evidence import wire_execution
        context,_=context_fixture();wire=wire_execution(dataclasses.replace(context.assessment_inputs,evidence_members=()))
        raw=wire[0][0]['raw'];stage=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        ledger=collection.Ledger();recorder=producer.AssessmentRecorder(stage,context)
        from unittest import mock
        import os
        def inner(manifest,vectors,*,rebuild,step):
            event=ev.decode((stage/'journal.jsonl').read_bytes(),canonical=True)
            self.assertEqual(event['event'],'started')
            self.assertGreater(flush.call_count,0)
            ledger.no_envelope(ledger.register(step=step))
            return ca._ProcessExecution(raw['built'],'safe',raw['outcomes'],raw['diagnostics'],raw['raised'],{})
        inner.execution_profile=ev.PROFILE;inner.accepts_step=True
        with mock.patch.object(os,'fsync',wraps=os.fsync) as flush:
            result=recorder.wrap(inner,ledger)({},[{}],rebuild=True,step=raw['step'])
        self.assertEqual(len(recorder.observations),1)
        retained=ev.decode((stage/'base/observations/0.json').read_bytes(),canonical=True)
        self.assertEqual(retained['raw'],raw)
        self.assertEqual(retained['state'],'returned');self.assertIsNone(retained['envelope'])
        self.assertEqual([ev.decode(line)['event'] for line in (stage/'journal.jsonl').read_bytes().splitlines()],['started','returned'])
        view=ev.decode((stage/'base/views/0.json').read_bytes(),canonical=True)
        self.assertEqual(view['observation']['sha256'],ev.digest((stage/'base/observations/0.json').read_bytes()))
        self.assertIs(result.built,True)

    def test_exception_settles_once_and_never_exports_message(self):
        import tempfile
        import owned_suggestion_assessment as producer
        import envelope_collection as collection
        context,_=context_fixture();stage=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        recorder=producer.AssessmentRecorder(stage,context);ledger=collection.Ledger()
        def inner(manifest,vectors,*,rebuild,step):
            ledger.raised(ledger.register(step=step),'RuntimeError')
            raise RuntimeError('/Users/private-secret')
        inner.execution_profile=ev.PROFILE;inner.accepts_step=True
        backend=recorder.wrap(inner,ledger)
        step=ev.decode(dict(context.assessment_inputs.retained_members)['plan.json'])['slots'][0]['step']
        with self.assertRaises(RuntimeError):backend({},[{}],step=step)
        raw=(stage/'base/observations/0.json').read_bytes()
        self.assertNotIn(b'private-secret',raw)
        self.assertEqual(ev.decode(raw)['state'],'exception')
        self.assertEqual(len((stage/'journal.jsonl').read_bytes().splitlines()),2)
        self.assertFalse((stage/'base/views/0.json').exists())


class EngineControlObservation(RealDriverEngine):
    def test_actual_evaluated_and_interrupted_events_survive_later_exceptions(self):
        for failure_slot in (1,2,3,None):
            events=[]
            with self.subTest(failure_slot=failure_slot):
                self._drive(failure_slot=failure_slot,control_observer=events.append)
                expected=[]
                for ordinal,control_id,polarity,verdict in (
                    (1,'control-positive','positive','control-killed'),
                    (2,'control-inert','inert','control-unchanged')):
                    if failure_slot is not None and ordinal>failure_slot:break
                    interrupted=ordinal==failure_slot
                    expected.append({'group':'independent','id':control_id,'polarity':polarity,
                        'state':'interrupted' if interrupted else 'evaluated',
                        'verdict':None if interrupted else verdict})
                self.assertEqual(events,expected)

    def test_observer_failure_does_not_replace_original_backend_exception(self):
        def observer(event):raise ValueError('secondary observer failure')
        self._drive(failure_slot=1,control_observer=observer)
