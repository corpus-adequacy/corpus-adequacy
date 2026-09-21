"""Operator verbs use the same execution API; ordinary measurement stays scored."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import corpus_adequacy as ca
import execution_observation as codec
from test_observation_prefix import corpus, D, E
from test_observation_resume import make_admission


@unittest.skipIf(ca.fcntl is None, 'observation execution requires POSIX advisory locks')
class ObservationCLI(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.manifest=corpus(self.root/'subject')
        (self.root/'context').write_bytes(b'context'); (self.root/'decision').write_bytes(b'decision')

    def command(self,*args):
        return subprocess.run([sys.executable,ca.__file__,*map(str,args)],capture_output=True,timeout=20)

    def prefix(self,*extra):
        return self.command('observe-prefix',self.manifest,'--profile','trusted-local',
            '--context',self.root/'context','--policy-identity',D,'--interpreter-identity',E,
            '--output-root',self.root/'prefix',*extra)

    def test_real_cli_prefix_resume_exact_artifact(self):
        result=self.prefix(); self.assertEqual(result.returncode,0,result.stderr.decode())
        receipt=json.loads(result.stdout); self.assertEqual(result.stdout,codec.canonical_bytes(receipt))
        prefix=Path(receipt['artifact_path']); self.assertEqual(receipt['artifact_sha256'],codec.sha256(prefix.read_bytes()))
        self.assertEqual(receipt['phase'],'awaiting_admission')
        admission=make_admission(prefix)
        resumed=self.command('observe-resume',self.manifest,'--prefix',prefix,'--admission',admission,
            '--context',self.root/'context','--decision',self.root/'decision','--profile','trusted-local',
            '--ledger-root',self.root/'ledger','--output-root',self.root/'final')
        self.assertEqual(resumed.returncode,0,resumed.stderr.decode())
        final=codec.load_observation(Path(json.loads(resumed.stdout)['artifact_path']).read_bytes(),kind='final')
        self.assertEqual([slot['outcome'] for slot in final['steps'][-1]['slots']],[9,9])
        self.assertNotIn('adequate',final)

    def test_close_refusal_does_not_execute(self):
        result=self.prefix(); self.assertEqual(result.returncode,0,result.stderr.decode())
        prefix=Path(json.loads(result.stdout)['artifact_path']); refusal=make_admission(prefix,'refuse')
        result=self.command('observe-close',prefix,'--admission',refusal,'--context',self.root/'context',
            '--decision',self.root/'decision','--output-root',self.root/'closed')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['phase'],'refused')

    def test_manifest_mode_and_contained_cli_refuse_before_evidence(self):
        doc=json.loads(self.manifest.read_bytes()); doc['observation_mode']=True
        self.manifest.write_text(json.dumps(doc))
        result=self.prefix(); self.assertEqual(result.returncode,2)
        self.assertFalse((self.root/'prefix').exists())
        self.assertEqual(json.loads(result.stdout)['operation'],'observe-prefix')
        result=self.prefix('--profile','contained-oci-v1'); self.assertEqual(result.returncode,2)
        self.assertFalse((self.root/'prefix').exists())

    def test_stopped_prefix_exit_one_retains_artifact(self):
        doc=json.loads(self.manifest.read_bytes()); doc['build']=[sys.executable,'-c','raise SystemExit(4)']
        self.manifest.write_text(json.dumps(doc))
        result=self.prefix(); self.assertEqual(result.returncode,1,result.stderr.decode())
        receipt=json.loads(result.stdout); self.assertEqual(receipt['phase'],'stopped')
        codec.load_observation(Path(receipt['artifact_path']).read_bytes(),kind='prefix')
        closed=self.command('observe-close',receipt['artifact_path'],'--output-root',self.root/'closed')
        self.assertEqual(closed.returncode,1,closed.stderr.decode())
        self.assertEqual(json.loads(closed.stdout)['phase'],'stopped')

    def test_existing_scored_cli_still_reports_adequacy(self):
        result=self.command(self.manifest,'--json')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        doc=json.loads(result.stdout); self.assertTrue(doc['adequate'])
        self.assertEqual(doc['score_percent'],100.0)
        self.assertNotIn('execution-observation',doc.get('schema',''))


if __name__=='__main__':unittest.main()
