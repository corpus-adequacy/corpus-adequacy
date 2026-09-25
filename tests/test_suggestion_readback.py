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



class ReaderCLI(unittest.TestCase):
    def run_cli(self, *args):
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(ROOT/'measurements/suggestion_readback.py'), *args],
                cwd=folder, env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1'),
                capture_output=True, timeout=5)
        self.assertLessEqual(len(result.stdout), 65536)
        self.assertLessEqual(len(result.stderr), 65536)
        return result

    def test_unknown_command_returns_closed_json_argument_refusal(self):
        result=self.run_cli('not-a-command')
        self.assertEqual(result.returncode,2)
        doc=ev.decode(result.stdout,canonical=True)
        self.assertEqual(doc,{'schema':ev.PREFIX+'reader-result.v0','load':'invalid',
            'internal_consistency':'not-evaluated','expected_identity':'not-evaluated',
            'reference_approval':'not-evaluated','replay_disposition':'not-evaluated',
            'origin':'unverified','reasons':[{'stage':'input','code':'argument-invalid','member':None}]})


def package_fixture(*, state='recorded', review=None, proposal_id='proposal'):
    """Synthetic final bytes; gate oracle is literal, not evaluator output."""
    from test_suggestion_evidence import full_fixture, fixture_engine_events
    inputs, (observations, views, controls, journal) = full_fixture(state=state,proposal_id=proposal_id)
    members = dict(inputs.retained_members + inputs.evidence_members)
    plan = ev.decode(members['plan.json'])
    def ref(path):
        return {'member': path, 'sha256': ev.digest(members[path]), 'bytes': len(members[path])}
    view_paths = []
    for kind, records in (('observations', observations), ('views', views)):
        for record in records:
            slot = record['slot']; path = f"{slot['variant']}/{kind}/{slot['ordinal']}.json"
            members[path] = ev.encode(record)
            if kind == 'views': view_paths.append(path)
    witnesses = ((), (), (), (0,4), (1,2,5,6), (3,7), tuple(range(8)), (), ())
    gates = [{'id': n, 'status': 'not-run' if n == 7 else 'passed',
              'reason': 'missing-review' if n == 7 else None,
              'witnesses': [plan['slots'][i] for i in indices]} for n, indices in enumerate(witnesses)]
    members['journal.jsonl'] = b''.join(ev.encode(e) for e in journal)
    members['gates.json'] = ev.encode({'schema': ev.PREFIX+'gates.v0',
        'plan_sha256': ev.digest(members['plan.json']), 'policy': ev.POLICY,
        'views': [ref(p) for p in view_paths], 'engine_controls': controls,
        'engine_control_events':fixture_engine_events(observations,controls),'gates': gates})
    rebind_final(members, review=review, disposition='unproved' if state != 'recorded' else None)
    expected = {'schema': ev.PREFIX+'expected.v0', 'plan_sha256': ev.digest(members['plan.json']),
        'source_content_sha256': plan['source']['content_sha256'],
        'reference_sha256': ev.digest(members['reference.json']), 'policy': ev.POLICY,
        'receipt_sha256': None, 'source_files': plan['source']['files'], 'reference_approval': 'accept'}
    return members, inputs.basis_members, expected


def rebind_final(members, *, review=None, disposition=None):
    """Repair internal digest graph for attacks; external E/B never change."""
    def sha(path): return ev.digest(members[path])
    plan_hash = sha('plan.json')
    indexed = sorted(set(members)-{'evidence-index.json','decision.json','receipt.json','review.json'})
    members['evidence-index.json'] = ev.encode({'schema': ev.PREFIX+'evidence-index.v0',
        'plan_sha256': plan_hash, 'members': [{'member': p, 'sha256': sha(p), 'bytes': len(members[p])} for p in indexed],
        'gate_result_sha256': sha('gates.json'), 'journal_sha256': sha('journal.jsonl')})
    if review is not None:
        members['review.json'] = ev.encode({'schema': ev.PREFIX+'review.v0',
            'proposal_sha256': sha('proposal.json'), 'evidence_index_sha256': sha('evidence-index.json'),
            'reviewer': 'synthetic-only', 'decision': review, 'rationale': 'Synthetic fixture only'})
    review_hash = sha('review.json') if 'review.json' in members else None
    if disposition is None:
        disposition = {None:'pending-review','accept':'eligible-for-human-corpus-PR','reject':'refused'}[review]
    members['decision.json'] = ev.encode({'schema':ev.PREFIX+'decision.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':sha('evidence-index.json'), 'gates_sha256':sha('gates.json'),
        'review_sha256':review_hash,'disposition':disposition})
    plan=ev.decode(members['plan.json'])
    members['receipt.json'] = ev.encode({'schema':ev.PREFIX+'receipt.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':sha('evidence-index.json'),'decision_sha256':sha('decision.json'),
        'review_sha256':review_hash,'family':ev.FAMILY,'profile':ev.PROFILE,
        'source_content_sha256':plan['source']['content_sha256'],'origin':'producer-reported'})


def refresh_package_refs(members, *, review=None, disposition=None):
    """Rebind retained wire digests, without computing projections or gates."""
    def ref(path):return {'member':path,'sha256':ev.digest(members[path]),'bytes':len(members[path])}
    view_paths=[]
    for v in ev.VARIANTS:
        for i in range(4):
            path=f'{v}/views/{i}.json'
            if path not in members:continue
            doc=ev.decode(members[path]);doc['observation']=ref(f'{v}/observations/{i}.json')
            members[path]=ev.encode(doc);view_paths.append(path)
    journal=[ev.decode(line) for line in members['journal.jsonl'].splitlines(keepends=True)]
    for event in journal:
        if event['event'] in ('returned','exception'):
            slot=event['slot'];event['observation']=ref(f"{slot['variant']}/observations/{slot['ordinal']}.json")
    members['journal.jsonl']=b''.join(ev.encode(e) for e in journal)
    gates=ev.decode(members['gates.json']);gates['views']=[ref(p) for p in view_paths]
    members['gates.json']=ev.encode(gates)
    rebind_final(members,review=review,disposition=disposition)


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class PackageCLI(ReaderCLI):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.package=self.root/'package';self.basis=self.root/'basis';self.expected=self.root/'expected.json'
        self.members,self.basis_members,self.expected_doc=package_fixture()

    def install(self):
        for root, members in ((self.package,self.members.items()),(self.basis,self.basis_members)):
            if root.exists(): shutil.rmtree(root)
            root.mkdir()
            for path,raw in members:
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        self.expected.write_bytes(ev.encode(self.expected_doc))
        self.assertLess(sum(len(b) for b in self.members.values()),4*1024*1024)

    def verify(self, *, mode='audit', anchored=True):
        self.install()
        result=self.run_cli('verify','--package',str(self.package),'--basis-dir',str(self.basis),
            '--mode',mode,*(['--expected',str(self.expected)] if anchored else ['--unanchored']))
        self.assertEqual(result.stderr,b'')
        return result.returncode,ev.decode(result.stdout,canonical=True)

    def test_complete_package_is_replayed_from_cli(self):
        for mode,anchored in (('audit',True),('audit',False),('handoff',True)):
            with self.subTest(mode=mode,anchored=anchored):
                code,doc=self.verify(mode=mode,anchored=anchored)
                self.assertEqual((code,doc['load'],doc['internal_consistency'],doc['replay_disposition']),
                    (0,'complete','match','pending-review'),doc)
                self.assertEqual(doc['expected_identity'],'match' if anchored else 'not-supplied')
                self.assertEqual(doc['reference_approval'],'accept' if anchored else 'not-supplied')
                self.assertEqual(doc['origin'],'unverified');self.assertEqual(doc['reasons'],[])

    def test_stored_gate_and_final_tampering_is_not_authoritative(self):
        for member,change,reason in (
            ('gates.json',lambda d:d['gates'][7].update(status='passed',reason=None),'gate-mismatch'),
            ('decision.json',lambda d:d.update(disposition='refused'),'decision-mismatch'),
            ('receipt.json',lambda d:d.update(decision_sha256='0'*64),'receipt-mismatch')):
            self.members,self.basis_members,self.expected_doc=package_fixture()
            doc=ev.decode(self.members[member]);change(doc);self.members[member]=ev.encode(doc)
            if member=='gates.json':rebind_final(self.members)
            with self.subTest(member=member):
                code,result=self.verify(anchored=False)
                self.assertEqual(code,1,result)
                self.assertIn(reason,[r['code'] for r in result['reasons']])

    def test_review_and_truthful_unproved_are_successful_inspections(self):
        for review,state,want in ((None,'recorded','pending-review'),('accept','recorded','eligible-for-human-corpus-PR'),
                                   ('reject','recorded','refused'),('accept','no-envelope','unproved')):
            self.members,self.basis_members,self.expected_doc=package_fixture(state=state,review=review)
            code,result=self.verify()
            self.assertEqual((code,result['internal_consistency'],result['replay_disposition']),(0,'match',want),result)
            self.assertEqual(ev.decode(self.members['gates.json'])['gates'][7]['status'],'not-run')

    def test_audit_never_short_circuits_for_expected_mismatch_or_approval(self):
        self.expected_doc['source_files'][0]['sha256']='d'*64
        gate=ev.decode(self.members['gates.json']);gate['gates'][5]['status']='refused';gate['gates'][5]['reason']='target-no-distinction'
        self.members['gates.json']=ev.encode(gate);rebind_final(self.members)
        code,result=self.verify()
        self.assertEqual((code,result['expected_identity'],result['internal_consistency']),(1,'mismatch','mismatch'),result)
        self.assertEqual([r['code'] for r in result['reasons']],['gate-mismatch','expected-identity-mismatch'])
        code,result=self.verify(mode='handoff')
        self.assertEqual((code,result['internal_consistency'],result['replay_disposition']),(1,'not-evaluated','not-evaluated'))
        self.members,self.basis_members,self.expected_doc=package_fixture()
        for approval,want,exitcode in (('unavailable','not-supplied',0),('reject','reject',1)):
            self.expected_doc['reference_approval']=approval
            code,result=self.verify()
            self.assertEqual((code,result['reference_approval'],result['internal_consistency']),(exitcode,want,'match'))
            code,result=self.verify(mode='handoff')
            self.assertEqual((code,result['internal_consistency']),(2,'not-evaluated'))
            self.assertEqual(result['reasons'][0]['code'],'reference-rejected' if approval=='reject' else 'reference-required')

    def test_closed_inventory_and_crash_precedence(self):
        for missing in ('receipt.json','base/prepare.json','base/envelopes/member-0003.json','base/views/3.json'):
            original=self.members.pop(missing)
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'incomplete','missing-member'),result)
            self.members[missing]=original
        for extra in ('extra.json','base/corpus/extra.json'):
            self.members[extra]=b'{}\n';code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load']),(2,'invalid'))
            self.assertEqual(result['reasons'][0]['code'],'entry-count' if '/corpus/' in extra else 'surplus-member')
            del self.members[extra]
        raw=self.members['journal.jsonl']
        self.members['journal.jsonl']=raw[:-1]
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'incomplete','partial-event'))
        self.members['journal.jsonl']=raw.splitlines(keepends=True)[0]
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'incomplete','unsettled-attempt'))
        self.members['journal.jsonl']=b'{bad}\n'
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'invalid','invalid-json'))

    def test_semantic_disagreements_have_no_fabricated_evaluation(self):
        for member,change,reason in (
            ('proposal.json',lambda d:d['vector']['document'].update(value=True),'preflight-refused'),
            ('base/views/0.json',lambda d:d['rows']['allow'].update(accepted=False),'raw-view-mismatch'),
            ('gates.json',lambda d:d['engine_controls'][0].update(positive='failed'),'engine-control-mismatch')):
            self.members,self.basis_members,self.expected_doc=package_fixture()
            doc=ev.decode(self.members[member]);change(doc);self.members[member]=ev.encode(doc)
            if member=='proposal.json':
                plan=ev.decode(self.members['plan.json'])
                plan['proposal'].update(sha256=ev.digest(self.members[member]),bytes=len(self.members[member]))
                self.members['plan.json']=ev.encode(plan)
                gates=ev.decode(self.members['gates.json']);gates['plan_sha256']=ev.digest(self.members['plan.json'])
                self.members['gates.json']=ev.encode(gates)
            if '/views/' in member:
                gates=ev.decode(self.members['gates.json'])
                for ref in gates['views']:
                    if ref['member']==member:ref.update(sha256=ev.digest(self.members[member]),bytes=len(self.members[member]))
                self.members['gates.json']=ev.encode(gates)
            rebind_final(self.members)
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load'],result['internal_consistency'],result['replay_disposition']),
                (1,'complete','mismatch','not-evaluated'),result)
            self.assertEqual(result['reasons'][0]['code'],reason)

    def test_rebound_observation_route_or_profile_change_is_refused(self):
        # Route/profile are outside the projection and all digests are rebound, so only these
        # checks refuse. The fixture expectation has no receipt pin (#235). A profile that
        # disagrees with the package's own declared profile is a contradiction; a route has no
        # declared counterpart in the package and stays an unsupported input.
        self.assertIsNone(self.expected_doc['receipt_sha256'])
        refusal={'profile':(1,'complete','mismatch',
                            [{'stage':'binding','code':'observation-profile','member':None}]),
                 'route':(2,'unsupported','not-evaluated',
                          [{'stage':'support','code':'unsupported-profile','member':None}])}
        for member in ('base/observations/0.json','outer-whitespace/observations/3.json'):
            for field,value in (('profile','contained-oci-v0'),('route','contained-oci-v1')):
                self.members,self.basis_members,self.expected_doc=package_fixture()
                doc=ev.decode(self.members[member]);doc[field]=value;self.members[member]=ev.encode(doc)
                refresh_package_refs(self.members)
                for mode,anchored in (('audit',False),('audit',True),('handoff',True)):
                    with self.subTest(member=member,field=field,mode=mode,anchored=anchored):
                        code,result=self.verify(mode=mode,anchored=anchored)
                        self.assertEqual((code,result['load'],result['internal_consistency'],result['reasons']),
                            refusal[field],result)
                        self.assertEqual(result['replay_disposition'],'not-evaluated')
                        self.assertEqual(result['expected_identity'],'match' if anchored else 'not-supplied')

    def test_new_metadata_and_support_are_strict(self):
        for raw,stage,reason,load in (
            (b'{"x":1,"x":2}\n','syntax','duplicate-key','invalid'),
            (b'{"x":NaN}\n','syntax','invalid-number','invalid'),
            (b'\xff','syntax','invalid-utf8','invalid')):
            original=self.members['receipt.json'];self.members['receipt.json']=raw
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load'],result['reasons'][0]['stage'],result['reasons'][0]['code']),
                             (2,load,stage,reason),result)
            self.members['receipt.json']=original
        import json
        for member in ('gates.json','receipt.json','base/views/0.json'):
            original=self.members[member];doc=ev.decode(original)
            self.members[member]=(json.dumps(doc,indent=2)+'\n').encode()
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['reasons'][0]['code']),(2,'noncanonical-new-object'),result)
            doc['schema']='unsupported';self.members[member]=ev.encode(doc)
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'unsupported','unsupported-schema'),result)
            self.members[member]=original

    def test_external_receipt_expectation_is_not_generated_from_package(self):
        self.expected_doc['receipt_sha256']='0'*64
        code,result=self.verify()
        self.assertEqual((code,result['expected_identity'],result['internal_consistency']),(1,'mismatch','match'))
        self.assertEqual(result['replay_disposition'],'pending-review')

    def test_installed_entrypoint_no_pythonpath_no_input_writes(self):
        import subprocess
        self.install();before=reader.load_package(self.package)
        args=[sys.executable,'-I',str(ROOT/'measurements/suggestion_readback.py'),'verify','--package',str(self.package),
            '--basis-dir',str(self.basis),'--mode','audit','--unanchored']
        # -I ignores PYTHONPATH and the script directory: bootstrap must cover both trusted roots.
        output=[]
        for _ in range(2):
            run=subprocess.run(args,cwd=self.root,capture_output=True,timeout=5)
            self.assertEqual(run.returncode,0,run.stderr+run.stdout);output.append(run.stdout)
        self.assertEqual(output[0],output[1]);self.assertEqual(reader.load_package(self.package),before)


    def test_valid_proposal_filename_is_derived_not_hardcoded(self):
        self.members,self.basis_members,self.expected_doc=package_fixture(proposal_id='new-witness')
        code,result=self.verify()
        self.assertEqual((code,result['internal_consistency']),(0,'match'),result)
        self.assertIn('base/corpus/new-witness.json',self.members)

    def test_missing_approved_review_is_incomplete(self):
        self.members,self.basis_members,self.expected_doc=package_fixture(review='accept')
        del self.members['review.json']
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'incomplete','missing-member'),result)


    def test_envelope_kernel_binding_and_legacy_raw_spelling_from_cli(self):
        import json
        for mutation,code,reason in (('pretty',0,None),('contradiction',2,'contradictory-record'),
                                      ('crossed',1,'envelope-binding'),('withheld',0,None)):
            self.members,self.basis_members,self.expected_doc=package_fixture()
            path='base/envelopes/member-0003.json';doc=ev.decode(self.members[path])
            if mutation in ('contradiction','withheld'):doc['cleanup']='remove-failed'
            if mutation=='withheld':doc.update(publication_permission='withheld',withheld_reason='cleanup')
            if mutation=='crossed':doc['prepare_sha256']='d'*64
            self.members[path]=(json.dumps(doc,indent=1)+'\n').encode()
            idxpath='base/envelopes/collection-index.v0.json';idx=ev.decode(self.members[idxpath])
            idx['members'][3]['sha256']=ev.digest(self.members[path]);self.members[idxpath]=ev.encode(idx)
            obs=ev.decode(self.members['base/observations/3.json'])
            obs['envelope'].update(sha256=ev.digest(self.members[path]),bytes=len(self.members[path]))
            self.members['base/observations/3.json']=ev.encode(obs)
            refresh_package_refs(self.members,disposition='unproved' if mutation=='withheld' else None)
            actual,result=self.verify(anchored=False)
            self.assertEqual(actual,code,(mutation,result))
            if reason:self.assertEqual(result['reasons'][0]['code'],reason)
            else:self.assertEqual(result['replay_disposition'],'unproved' if mutation=='withheld' else 'pending-review')

    def test_faithful_target_refusal_is_reproduced_and_cannot_be_promoted(self):
        for v in ev.VARIANTS:
            path=f'{v}/observations/3.json';doc=ev.decode(self.members[path])
            doc['raw']['outcomes']['<batch>'][0]['proposal']={'accepted':True,'reason':'within-range'}
            self.members[path]=ev.encode(doc)
            path=f'{v}/views/3.json';doc=ev.decode(self.members[path])
            doc['rows']['proposal']={'accepted':True,'reason':'within-range'};self.members[path]=ev.encode(doc)
        gates=ev.decode(self.members['gates.json'])
        gates['gates'][5].update(status='refused',reason='target-no-distinction')
        gates['gates'][6].update(status='not-run',reason='prerequisite-refused',witnesses=[])
        self.members['gates.json']=ev.encode(gates)
        refresh_package_refs(self.members,review='accept',disposition='refused')
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['internal_consistency'],result['replay_disposition']),(0,'match','refused'),result)
        gates['gates'][5].update(status='passed',reason=None);self.members['gates.json']=ev.encode(gates)
        refresh_package_refs(self.members,review='accept',disposition='eligible-for-human-corpus-PR')
        code,result=self.verify(anchored=False)
        self.assertEqual(code,1,result);self.assertEqual(result['replay_disposition'],'refused')
        self.assertIn('gate-mismatch',[r['code'] for r in result['reasons']])

    def test_stopped_execution_with_empty_unentered_collection_is_unproved(self):
        self.stop_after_backend_exception()
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['internal_consistency'],result['replay_disposition']),(0,'match','unproved'),result)

    def test_exception_observation_route_or_profile_change_is_refused(self):
        # The only retained observation is exception-state: the profile check in replay and
        # the route check in projection cover it too, not only returned observations (#235).
        refusal={'profile':(1,'complete','mismatch',
                            [{'stage':'binding','code':'observation-profile','member':None}]),
                 'route':(2,'unsupported','not-evaluated',
                          [{'stage':'support','code':'unsupported-profile','member':None}])}
        for field,value in (('profile','contained-oci-v0'),('route','contained-oci-v1')):
            with self.subTest(field=field):
                self.members,self.basis_members,self.expected_doc=package_fixture()
                self.stop_after_backend_exception()
                doc=ev.decode(self.members['base/observations/0.json'])
                self.assertEqual(doc['state'],'exception')
                doc[field]=value;self.members['base/observations/0.json']=ev.encode(doc)
                refresh_package_refs(self.members,review='accept',disposition='unproved')
                code,result=self.verify(anchored=False)
                self.assertEqual((code,result['load'],result['internal_consistency'],result['reasons']),
                                 refusal[field],result)

    def stop_after_backend_exception(self):
        """Valid unproved package: slot 0 raised, every later slot not started."""
        import copy
        plan=ev.decode(self.members['plan.json']);slot=plan['slots'][0]
        doc=ev.decode(self.members['base/observations/0.json'])
        doc.update(state='exception',raw=None,exception_kind='backend-exception',envelope=None)
        self.members['base/observations/0.json']=ev.encode(doc)
        for path in list(self.members):
            if '/views/' in path or ('/observations/' in path and path!='base/observations/0.json') or '/envelopes/member-' in path:
                del self.members[path]
        for v in ev.VARIANTS:
            path=v+'/envelopes/collection-index.v0.json';idx=ev.decode(self.members[path])
            idx.update(attempts=1 if v=='base' else 0,members=[],execution_commit=None,prepare_sha256=None)
            idx['ledger']=idx['ledger'][:1] if v=='base' else []
            if idx['ledger']:idx['ledger'][0].update(state='raised',returncode=None,exception_type='RuntimeError')
            self.members[path]=ev.encode(idx)
        journal=[ev.decode(line) for line in self.members['journal.jsonl'].splitlines(keepends=True)][:2]
        journal[1].update(event='exception',reason='backend-exception')
        for omitted in plan['slots'][1:]:
            journal.append({'schema':ev.PREFIX+'journal-event.v0','plan_sha256':ev.digest(self.members['plan.json']),
                'seq':len(journal),'slot':omitted,'event':'not-started','reason':'prerequisite-refused','observation':None})
        self.members['journal.jsonl']=b''.join(ev.encode(e) for e in journal)
        gates=ev.decode(self.members['gates.json'])
        gates['gates'][3].update(status='refused',reason='abnormal-execution',witnesses=[copy.deepcopy(slot)])
        for i in (4,5,6):gates['gates'][i].update(status='not-run',reason='prerequisite-refused',witnesses=[])
        for control in gates['engine_controls']:control.update(positive='not-run',inert='not-run',barrier='stop')
        gates['engine_control_events']=[]
        self.members['gates.json']=ev.encode(gates)
        refresh_package_refs(self.members,review='accept',disposition='unproved')

    def test_review_binding_and_journal_or_ledger_schedule_are_checked(self):
        self.members,self.basis_members,self.expected_doc=package_fixture(review='accept')
        review=ev.decode(self.members['review.json']);review['proposal_sha256']='d'*64
        self.members['review.json']=ev.encode(review);rebind_final(self.members,disposition='eligible-for-human-corpus-PR')
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['reasons'][0]['code'],result['replay_disposition']),(1,'review-binding','not-evaluated'),result)
        for member in ('journal.jsonl','base/envelopes/collection-index.v0.json'):
            self.members,self.basis_members,self.expected_doc=package_fixture()
            if member=='journal.jsonl':self.members[member]+=self.members[member].splitlines(keepends=True)[-1]
            else:
                idx=ev.decode(self.members[member]);idx['ledger'][1]['previous_member_sha256']='0'*64
                self.members[member]=ev.encode(idx)
            rebind_final(self.members)
            code,result=self.verify(anchored=False)
            self.assertEqual((code,result['load'],result['reasons'][0]['code']),(2,'invalid','schedule-mismatch'),result)


    def test_index_hash_is_checked_against_original_raw_bytes(self):
        index=ev.decode(self.members['evidence-index.json'])
        index['members'][0]['sha256']='0'*64
        self.members['evidence-index.json']=ev.encode(index)
        code,result=self.verify(anchored=False)
        self.assertEqual((code,result['internal_consistency'],result['reasons'][0]['code']),
                         (1,'mismatch','member-digest'),result)


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class PackageFilesystem(unittest.TestCase):
    setUp = PackageCLI.setUp
    install = PackageCLI.install
    def test_package_unsafe_members_and_ancestors(self):
        self.install()
        def check(reason):
            with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
            self.assertEqual(caught.exception.code,reason)
        target=self.package/'receipt.json';raw=target.read_bytes();outside=self.root/'outside';outside.write_bytes(raw)
        for kind in ('symlink','hardlink','fifo','directory'):
            target.unlink()
            if kind=='symlink':target.symlink_to(outside)
            elif kind=='hardlink':os.link(outside,target)
            elif kind=='fifo':os.mkfifo(target)
            else:target.mkdir()
            check('nonregular-member')
            if target.is_dir():target.rmdir()
            else:target.unlink()
            target.write_bytes(raw)
        linked=self.root/'linked';linked.symlink_to(self.package,target_is_directory=True)
        with self.assertRaises(ev.EvidenceError):reader.load_package(linked)
        extra=self.package/'base/views/extra';extra.mkdir();check('surplus-member');extra.rmdir()
        target=self.package/'RECEIPT.json'
        if not target.exists():target.write_bytes(raw);check('duplicate-member')

    def test_snapshot_replacement_and_reduced_limits(self):
        self.install()
        original_read=os.read;replaced=False
        def replace(fd,count):
            nonlocal replaced
            raw=original_read(fd,count)
            if not replaced:
                replaced=True
                target=self.package/'authorization.json';replacement=self.root/'replacement'
                replacement.write_bytes(target.read_bytes());os.replace(replacement,target)
            return raw
        with mock.patch.object(reader.os,'read',side_effect=replace):
            with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
        self.assertEqual(caught.exception.code,'nonregular-member')
        for attr,value,reason in (
            ('PACKAGE_BYTES',1,'aggregate-bytes'),('PACKAGE_FILES',1,'entry-count'),
            ('PACKAGE_DIRECTORIES',1,'entry-count'),('PACKAGE_DEPTH',1,'path-depth'),
            ('CATEGORY_BYTES',dict(reader.CATEGORY_BYTES,metadata=1),'category-bytes')):
            with mock.patch.object(reader,attr,value):
                with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
                self.assertEqual(caught.exception.code,reason)
        raw=self.members['receipt.json'];self.members['receipt.json']=b' '*65537;self.install()
        with mock.patch.object(reader.ev,'decode',side_effect=AssertionError('must cap before parsing')):
            with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
        self.assertEqual(caught.exception.code,'member-bytes')
        self.members['receipt.json']=raw


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class OfflineBoundary(unittest.TestCase):
    setUp=PackageCLI.setUp
    install=PackageCLI.install
    run_cli=ReaderCLI.run_cli

    def test_cli_arguments_and_help(self):
        for args,reason in (((), 'argument-invalid'),(('verify',),'argument-invalid'),
            (('verify','--package','p','--basis-dir','b'),'expected-required'),
            (('verify','--package','p','--basis-dir','b','--expected','e','--unanchored'),'argument-invalid'),
            (('verify','--package','p','--basis-dir','b','--mode','audit'),'expected-required'),
            (('verify','--package','p','--basis-dir','b','--unanchored'),'expected-required')):
            result=self.run_cli(*args)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertEqual(ev.decode(result.stdout)['reasons'][0]['code'],reason)
        help_result=self.run_cli('verify','--help')
        self.assertEqual(help_result.returncode,0);self.assertIn(b'--basis-dir',help_result.stdout)

    def test_whole_cli_dependency_closure_is_offline(self):
        import subprocess
        self.install()
        setup=f'''
import sys,runpy,importlib.abc
sys.dont_write_bytecode=True
sys.path[:0]=[{str(ROOT)!r},{str(ROOT/'measurements')!r}]
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in {{'subprocess','socket','contained_oci','bounded_run','corpus_adequacy',
                'effective_envelope','envelope_collection','suggestion_admission','suggestion_execution',
                'aee_checker_sealed_candidate','aee_checker_sealed_run'}}:
            raise RuntimeError('FORBIDDEN_IMPORT')
sys.meta_path.insert(0,Guard())
def audit(event,args):
    if event.startswith(('subprocess.','socket.','os.spawn','os.exec')) or event=='os.system':
        raise RuntimeError('FORBIDDEN_EFFECT')
sys.addaudithook(audit)
sys.argv=[{str(ROOT/'measurements/suggestion_readback.py')!r},'verify','--package',{str(self.package)!r},
    '--basis-dir',{str(self.basis)!r},'--mode','audit','--unanchored']
'''
        for effect in ('pass',"__import__('contained_oci')","__import__('socket')","__import__('subprocess')"):
            script=setup+'\n'+effect+f'\nrunpy.run_path({str(ROOT/"measurements/suggestion_readback.py")!r},run_name="__main__")'
            result=subprocess.run([sys.executable,'-I','-c',script],cwd=self.root,capture_output=True,timeout=5)
            if effect=='pass':
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(ev.decode(result.stdout)['internal_consistency'],'match')
            else:
                self.assertNotEqual(result.returncode,0);self.assertIn(b'FORBIDDEN_IMPORT',result.stderr)

    def test_one_evaluation_and_no_second_file_read(self):
        self.install()
        with mock.patch.object(ev,'evaluate_assessment',wraps=ev.evaluate_assessment) as judge, \
                mock.patch.object(reader,'_read_file',wraps=reader._read_file) as reads:
            result,code=reader.verify_package(self.package,self.basis,mode='audit')
        self.assertEqual(code,0,result);self.assertEqual(judge.call_count,1)
        self.assertEqual(reads.call_count,len(self.members)+6)

    def test_exact_and_reduced_budgets_use_identical_snapshot_path(self):
        self.install();total=sum(len(b) for b in self.members.values())
        category={k:0 for k in reader.CATEGORY_BYTES}
        for p,b in self.members.items():category[ev.package_member_kind(p)[0]]+=len(b)
        with mock.patch.object(reader,'PACKAGE_BYTES',total),mock.patch.object(reader,'CATEGORY_BYTES',category):
            self.assertEqual(dict(reader.load_package(self.package)),self.members)
        with mock.patch.object(reader,'PACKAGE_BYTES',total-1):
            with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
            self.assertEqual(caught.exception.code,'aggregate-bytes')
        target=self.package/'receipt.json';target.write_bytes(b' '*65536)
        self.assertEqual(len(dict(reader.load_package(self.package))['receipt.json']),65536)
        target.write_bytes(b' '*65537)
        with self.assertRaises(ev.EvidenceError) as caught:reader.load_package(self.package)
        self.assertEqual(caught.exception.code,'member-bytes')

    def test_support_and_invalid_expected_have_closed_results(self):
        self.install()
        with mock.patch.object(reader.os,'supports_dir_fd',set()):
            result,code=reader.verify_package(self.package,self.basis,mode='audit')
        self.assertEqual((code,result['load'],result['internal_consistency']),(2,'unsupported','not-evaluated'))
        self.expected.write_bytes(b'{}\n')
        result,code=reader.verify_package(self.package,self.basis,expected=self.expected,mode='audit')
        self.assertEqual(code,2);self.assertEqual(result['reasons'][0]['code'],'expected-invalid')

    def test_unsafe_package_precedes_external_basis_semantic_mismatch(self):
        self.install()
        (self.basis/'LICENSE').write_bytes(b'changed original')
        target=self.package/'receipt.json';target.unlink();target.symlink_to(self.expected)
        result,code=reader.verify_package(self.package,self.basis,mode='audit')
        self.assertEqual((code,result['load'],result['internal_consistency']),
                         (2,'invalid','not-evaluated'),result)
        self.assertEqual(result['reasons'][0]['code'],'nonregular-member')

    def test_reason_bounds_keep_primary_and_deterministic_order(self):
        issues=[('replay','gate-mismatch',p) for p in sorted(ev.PACKAGE_PATHS)]
        issues.append(('filesystem','missing-member','receipt.json'))
        result=reader._reasons(issues)
        self.assertEqual(len(result),32)
        self.assertEqual(result[0],{'stage':'filesystem','code':'missing-member','member':'receipt.json'})
        self.assertEqual(result[-1],{'stage':'result','code':'reasons-truncated','member':None})
        self.assertEqual(result,reader._reasons(list(reversed(issues))))


if __name__ == '__main__':
    unittest.main()


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
                     and os.scandir in os.supports_fd, 'safe descriptor filesystem required')
class AncestorIdentity(unittest.TestCase):
    def test_sibling_creation_does_not_change_selected_directory_identity(self):
        import tempfile
        import os
        import suggestion_readback as reader
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        target=root/'selected';target.mkdir();(target/'data').write_bytes(b'fixed')
        before=os.stat(root)
        with reader._directory(reader._absolute_parts(target)) as fd:
            (root/'unrelated-sibling').mkdir()
            after=os.stat(root)
            self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
            self.assertNotEqual(reader._signature(before),reader._signature(after))
            self.assertEqual(reader._read_file(fd,'data',remaining=100,seen=set()),b'fixed')

    def test_ancestor_replacement_still_refuses(self):
        import tempfile
        import suggestion_readback as reader
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        ancestor=root/'ancestor';ancestor.mkdir();target=ancestor/'selected';target.mkdir()
        with self.assertRaises(ev.EvidenceError):
            with reader._directory(reader._absolute_parts(target)):
                ancestor.rename(root/'moved');ancestor.mkdir();(ancestor/'selected').mkdir()

    def test_selected_directory_inventory_change_still_refuses(self):
        import tempfile
        import suggestion_readback as reader
        root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        target=root/'selected';target.mkdir()
        with self.assertRaises(ev.EvidenceError):
            with reader._directory(reader._absolute_parts(target)):
                (target/'surplus').write_bytes(b'x')
