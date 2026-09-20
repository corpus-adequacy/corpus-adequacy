"""Real ordinary-only continuation and durable one-use admission."""
import json
import multiprocessing
import subprocess
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


def make_admission(prefix, decision='allow'):
    doc = codec.load_observation(prefix.read_bytes(), kind='prefix')
    value = dict(schema=codec.ADMISSION_SCHEMA, session=doc['session'],
                 prefix_sha256=codec.sha256(prefix.read_bytes()),
                 context_sha256=codec.sha256(b'context'), decision_sha256=codec.sha256(b'decision'),
                 policy_identity=D, interpreter_identity=E, next_step=doc['schedule'][-1]['step_id'],
                 decision=decision, reasons=[] if decision=='allow' else ['policy-refused'], nonce='one')
    value['decision_binding_sha256']=codec.sha256(codec.canonical_bytes(value))
    path=prefix.parent/(decision+'.json'); path.write_bytes(codec.encode_observation(value))
    return path


def race_worker(barrier, queue, prefix, admission, manifest, root, number):
    barrier.wait()
    try:
        path=obs.resume_observation(Path(prefix),Path(admission),context_raw=b'context',decision_raw=b'decision',
            manifest_path=Path(manifest),execution_profile='trusted-local',backend=None,
            ledger_root=Path(root)/'ledger',output_root=Path(root)/str(number))
        queue.put(('ok',str(path)))
    except Exception as error:
        queue.put(('refused',type(error).__name__))


class ResumeExecution(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.manifest=corpus(self.root/'subject')
        self.prefix=obs.observe_prefix(self.manifest,execution_profile='trusted-local',context_raw=b'context',
            output_root=self.root/'prefix',policy_identity=D,interpreter_identity=E)
        self.admission=make_admission(self.prefix)

    def resume(self, **changes):
        kwargs=dict(context_raw=b'context',decision_raw=b'decision',manifest_path=self.manifest,
                    execution_profile='trusted-local',backend=None,ledger_root=self.root/'ledger',output_root=self.root/'final')
        kwargs.update(changes)
        return obs.resume_observation(self.prefix,self.admission,**kwargs)

    def test_allow_only_ordinary_and_original_source_restored(self):
        original=(self.manifest.parent/'subject.py').read_bytes()
        primitive=ca._execute_mutation_observation
        seen=[]
        def execute(session,group,mutant):
            seen.append(mutant['label']); return primitive(session,group,mutant)
        with mock.patch.object(ca,'_execute_mutation_observation',side_effect=execute):
            path=self.resume()
        doc=codec.load_observation(path.read_bytes(),kind='final')
        self.assertEqual(seen,['ordinary'])
        self.assertEqual(doc['phase'],'complete')
        self.assertEqual([v['outcome'] for v in doc['steps'][-1]['slots']],[9,9])
        self.assertEqual(doc['steps'][:-1],codec.load_observation(self.prefix.read_bytes(),kind='prefix')['steps'][:-1])
        self.assertEqual((self.manifest.parent/'subject.py').read_bytes(),original)
        with mock.patch.object(ca,'_execute_mutation_observation',side_effect=AssertionError('replay')):
            with self.assertRaises((ValueError,FileExistsError,ca.ManifestError)):
                self.resume(output_root=self.root/'different')

    def test_refuse_pure_and_published_closure_agree(self):
        refusal=make_admission(self.prefix,'refuse')
        raw=codec.prepare_closure(self.prefix.read_bytes(),admission_raw=refusal.read_bytes(),
                                  context_raw=b'context',decision_raw=b'decision')
        with mock.patch.object(ca,'_execute_mutation_observation',side_effect=AssertionError('execution')):
            path=obs.close_observation(self.prefix,admission_path=refusal,context_raw=b'context',
                                      decision_raw=b'decision',output_root=self.root/'closed')
        self.assertEqual(path.read_bytes(),raw)
        doc=codec.load_observation(raw,kind='final')
        self.assertEqual(doc['phase'],'refused')
        self.assertEqual([v['state'] for v in doc['steps'][-1]['slots']],['not_run']*2)
        with self.assertRaises(ValueError):
            codec.prepare_closure(self.prefix.read_bytes(),admission_raw=self.admission.read_bytes(),
                                  context_raw=b'context',decision_raw=b'decision')

    def test_binding_failures_never_consume_or_mutate(self):
        with mock.patch.object(ca,'_execute_mutation_observation',side_effect=AssertionError('execution')):
            for changes in ({'context_raw':b'wrong'},{'decision_raw':b'wrong'}, {'execution_profile':'contained-oci-v1'}):
                with self.subTest(changes=changes), self.assertRaises((ValueError,ca.ManifestError)):
                    self.resume(**changes)
            (self.manifest.parent/'subject.py').write_text('VALUE = 17\n')
            with self.assertRaises((ValueError,ca.ManifestError)): self.resume()
        self.assertFalse((self.root/'ledger').exists())

    def test_interrupted_dispatch_recovers_one_unknown_and_never_retries(self):
        original=(self.manifest.parent/'subject.py').read_bytes()
        with mock.patch.object(obs,'run_capped_bytes',side_effect=KeyboardInterrupt('after dispatch')):
            with self.assertRaises(KeyboardInterrupt): self.resume()
        with mock.patch.object(obs,'run_capped_bytes',side_effect=AssertionError('recovery executed')):
            path=obs.recover_observation(self.prefix,self.admission,context_raw=b'context',decision_raw=b'decision',
                manifest_path=self.manifest,ledger_root=self.root/'ledger',output_root=self.root/'recovered')
        doc=codec.load_observation(path.read_bytes(),kind='final')
        slots=doc['steps'][-1]['slots']
        self.assertEqual([(v['state'],v['reason']) for v in slots],[('abnormal','interrupted'),('not_run','interrupted')])
        self.assertIsNone(slots[0]['receipt'])
        self.assertIsNone(slots[0]['outcome'])
        self.assertEqual((self.manifest.parent/'subject.py').read_bytes(),original)
        with self.assertRaises((ValueError,FileExistsError,ca.ManifestError)): self.resume()

    def test_verified_first_receipt_survives_crash_on_second_vector(self):
        run=obs.run_capped_bytes; calls=[]
        def fail_second(*args,**kwargs):
            calls.append(True)
            if len(calls)==2: raise KeyboardInterrupt('second child')
            return run(*args,**kwargs)
        with mock.patch.object(obs,'run_capped_bytes',side_effect=fail_second):
            with self.assertRaises(KeyboardInterrupt): self.resume()
        path=obs.recover_observation(self.prefix,self.admission,context_raw=b'context',decision_raw=b'decision',
            manifest_path=self.manifest,ledger_root=self.root/'ledger',output_root=self.root/'recovered')
        doc=codec.load_observation(path.read_bytes(),kind='final')
        self.assertEqual([s['state'] for s in doc['steps'][-1]['slots']],['observed','abnormal'])
        self.assertEqual(doc['steps'][-1]['slots'][0]['outcome'],9)

    def interrupt(self):
        with mock.patch.object(obs,'run_capped_bytes',side_effect=KeyboardInterrupt('child')):
            with self.assertRaises(KeyboardInterrupt): self.resume()
        return next((self.root/'final').iterdir())

    def recover(self):
        return obs.recover_observation(self.prefix,self.admission,context_raw=b'context',decision_raw=b'decision',
            manifest_path=self.manifest,ledger_root=self.root/'ledger',output_root=self.root/'recovered')

    def test_missing_dispatch_refuses_final(self):
        root=self.interrupt(); (root/'dispatch-000000.json').unlink()
        with self.assertRaises((ValueError,ca.ManifestError)): self.recover()
        self.assertFalse((self.root/'recovered').exists())

    def test_swapped_dispatch_refuses_final(self):
        root=self.interrupt(); path=root/'dispatch-000000.json'
        doc=json.loads(path.read_bytes()); doc['vector_id']='v1'; path.write_bytes(codec.canonical_bytes(doc))
        with self.assertRaises((ValueError,ca.ManifestError)): self.recover()

    def test_two_unmatched_dispatches_refuse_final(self):
        root=self.interrupt(); doc=json.loads((root/'dispatch-000000.json').read_bytes())
        doc.update(ordinal=1,vector_id='v1',invocation_id='another')
        raw=codec.canonical_bytes(doc)
        (root/'dispatch-000001.json').write_bytes(raw)
        (root/'call-000001.intent.json').write_bytes(codec.canonical_bytes({'dispatch_sha256':codec.sha256(raw)}))
        with self.assertRaises((ValueError,ca.ManifestError)): self.recover()

    def test_failure_after_consumption_before_substitution_cannot_reuse(self):
        persist=obs._persist_new
        def fail_intent(path,raw):
            if path.name.endswith('.intent.json'): raise OSError('intent persistence')
            return persist(path,raw)
        with mock.patch.object(obs,'_persist_new',side_effect=fail_intent):
            with self.assertRaises(OSError): self.resume()
        with mock.patch.object(ca,'_execute_mutation_observation',side_effect=AssertionError('replay')):
            with self.assertRaises(FileExistsError): self.resume(output_root=self.root/'again')
        doc=codec.load_observation(self.recover().read_bytes(),kind='final')
        self.assertEqual([s['state'] for s in doc['steps'][-1]['slots']],['not_run']*2)

    def test_failure_publishing_final_retains_receipts_for_recovery(self):
        persist=obs._persist_new
        def fail_final(path,raw):
            if path.name=='final.json': raise OSError('final persistence')
            return persist(path,raw)
        with mock.patch.object(obs,'_persist_new',side_effect=fail_final):
            with self.assertRaises(OSError): self.resume()
        with mock.patch.object(obs,'run_capped_bytes',side_effect=AssertionError('replay')):
            doc=codec.load_observation(self.recover().read_bytes(),kind='final')
        self.assertEqual([s['outcome'] for s in doc['steps'][-1]['slots']],[9,9])
        self.assertEqual(doc['phase'],'stopped')

    def test_hard_process_death_keeps_unknown_cleanup_and_no_retry(self):
        script = """import os,sys
from pathlib import Path
import observation_session as obs
obs.run_capped_bytes=lambda *a,**k: os._exit(77)
obs.resume_observation(Path(sys.argv[1]),Path(sys.argv[2]),context_raw=b'context',decision_raw=b'decision',
 manifest_path=Path(sys.argv[3]),execution_profile='trusted-local',backend=None,
 ledger_root=Path(sys.argv[4])/'ledger',output_root=Path(sys.argv[4])/'final')
"""
        result=subprocess.run([sys.executable,'-c',script,str(self.prefix),str(self.admission),str(self.manifest),str(self.root)],
                              cwd=Path(obs.__file__).parent,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,77,result.stderr.decode())
        record=json.loads(next((self.root/'ledger').glob('*.consumed.json')).read_bytes())
        isolated=Path(record['isolated_root'])
        owner=ca.IsolatedMutationTree(self.manifest.parent); owner.root=isolated
        self.addCleanup(owner.cleanup)
        self.assertTrue(isolated.exists())
        doc=codec.load_observation(self.recover().read_bytes(),kind='final')
        self.assertFalse(doc['cleanup']['restored']); self.assertFalse(doc['cleanup']['isolated_tree_removed'])
        self.assertFalse(doc['steps'][-1]['restored'])
        self.assertEqual(doc['steps'][-1]['slots'][0]['reason'],'interrupted')
        self.assertIn('VALUE = 7',(self.manifest.parent/'subject.py').read_text())
        self.assertTrue(isolated.exists())

    def test_partial_dispatch_persistence_is_unclosed(self):
        persist=obs._persist_new
        def fail_dispatch(path,raw):
            if path.name.startswith('dispatch-'): raise OSError('dispatch fsync')
            return persist(path,raw)
        with mock.patch.object(obs,'_persist_new',side_effect=fail_dispatch):
            with self.assertRaises(OSError): self.resume()
        with self.assertRaises(ca.ManifestError): self.recover()

    def test_two_processes_with_distinct_outputs_consume_once(self):
        ctx=multiprocessing.get_context('spawn'); barrier=ctx.Barrier(2); queue=ctx.Queue()
        processes=[ctx.Process(target=race_worker,args=(barrier,queue,str(self.prefix),str(self.admission),
                    str(self.manifest),str(self.root),i)) for i in range(2)]
        for process in processes: process.start()
        for process in processes:
            process.join(30); self.assertEqual(process.exitcode,0)
        results=[queue.get(timeout=2)[0] for _ in processes]
        queue.close(); queue.join_thread()
        self.assertEqual(sorted(results),['ok','refused'])
        self.assertEqual(len(list((self.root/'ledger').glob('*.consumed.json'))),1)


if __name__=='__main__': unittest.main()
