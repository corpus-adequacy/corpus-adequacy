#!/usr/bin/env python3
"""Owned assessment producer. Explicit commands, external approval and retained bytes."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

_HERE = Path(__file__).absolute().parent
sys.path[:0] = [str(_HERE), str(_HERE.parent)]

import suggestion_evidence as ev
import suggestion_readback as reader

COMMANDS = ('plan', 'prepare', 'authorize', 'execute', 'finalize')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv and argv[0] in COMMANDS else 'invalid'
    result = {'schema': ev.PREFIX+'command-result.v0', 'command': command,
              'status': 'refused', 'artifacts': [], 'reasons': []}

    class Parser(argparse.ArgumentParser):
        def error(self, message):
            ev.refuse('input', 'argument-invalid')

    try:
        parser = Parser(prog='owned_suggestion_assessment', allow_abbrev=False)
        sub = parser.add_subparsers(dest='command', required=True)
        flags = {
            'plan': ('proposal','reference','reference-sha256','reference-approval','root','out','basis-dir'),
            'prepare': ('plan-dir','variant','image-id','inputs-dir','out','expected','basis-dir'),
            'authorize': ('plan-dir','base-prepare','whitespace-prepare','operator','out','expected','basis-dir'),
            'execute': ('plan-dir','authorization-dir','base-prepare-dir','whitespace-prepare-dir','out','expected','basis-dir'),
            'finalize': ('assessment-dir','out','expected','basis-dir'),
        }
        for name in COMMANDS:
            child = sub.add_parser(name, allow_abbrev=False)
            for flag in flags[name]:
                kwargs = {'required': True}
                if flag == 'variant': kwargs['choices'] = ev.VARIANTS
                if flag == 'reference-approval': kwargs['choices'] = ('accept','reject','unavailable')
                child.add_argument('--'+flag, **kwargs)
            if name == 'finalize':
                review = child.add_mutually_exclusive_group(required=True)
                review.add_argument('--review')
                review.add_argument('--pending-review', action='store_true')
        args = parser.parse_args(argv)
        result, code = dispatch(args)
    except ev.EvidenceError as exc:
        result['reasons'] = [{'stage': exc.stage, 'code': exc.code, 'member': None}]
        code = 2
    except Exception:
        result['reasons'] = [{'stage': 'input', 'code': 'internal-error', 'member': None}]
        code = 2
    sys.stdout.buffer.write(ev.encode(result))
    return code



def _read_input(path):
    reader._require_support()
    parts=reader._absolute_parts(path)
    if not parts:ev.refuse('input','argument-invalid')
    try:
        with reader._directory(parts[:-1]) as parent:
            return reader._read_file(parent,parts[-1],remaining=65536,seen=set())
    except OSError:
        ev.refuse('filesystem','unreadable')


def _plan_pins(plan_raw, root):
    plan=ev.decode(plan_raw,canonical=True);plan_hash=ev.digest(plan_raw)
    members={}
    for name,variant in zip(ev.VARIANTS,plan['variants']):
        for pin in ('control.json','sites.json','manifest.json'):
            raw=_read_input(Path(root)/'measurements/owned-independent-v0'/pin)
            if ev.digest(raw)!=ev._OWNED.pin_digest(pin):ev.refuse('binding','corpus-derivation')
            members[name+'/pins/'+pin]=raw
        pins={'schema':ev.PREFIX+'pins.v0','plan_sha256':plan_hash,'variant':name,
            'instrument_commit':plan['instrument_commit'],'subject_tree_sha256':plan['subject_tree_sha256'],
            'adapter_sha256':plan['adapter_sha256'],
            'corpus':{'kind':'local-derived-owned-v0','plan_sha256':plan_hash,'variant':name,
                'manifest_sha256':variant['manifest']['sha256'],'tree_sha256':variant['tree_sha256'],
                'corpus_digest':variant['corpus_digest'],'ids':[row['id'] for row in variant['vectors']]},
            'control_sha256':plan['control_sha256'],'sites_sha256':plan['sites_sha256'],
            'manifest_sha256':ev._OWNED.pin_digest('manifest.json')}
        members[name+'/pins/pins.json']=ev.encode(pins)
    return members


def _publish(members, dest):
    from aee_checker_sealed_materialize import begin_atomic_dest,commit_atomic_dest,abort_atomic_dest
    from aee_checker_sealed_common import PrepareError
    dest=Path(dest)
    try:
        # The read-only snapshot guard must end before our own directory writes.
        with reader._directory(reader._absolute_parts(dest)[:-1]):
            pass
        if dest.exists() or dest.is_symlink():ev.refuse('filesystem','surplus-member')
        state=begin_atomic_dest(dest)
        try:
            for member,raw in sorted(members.items()):
                _,cap=ev.package_member_kind(member)
                if len(raw)>cap:ev.refuse('limits','member-bytes')
                path=state['staging']/member;path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb') as stream:
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
            reader.load_package(state['staging'])
            commit_atomic_dest(state)
        except BaseException:
            abort_atomic_dest(state)
            raise
    except (OSError,PrepareError):
        ev.refuse('filesystem','unreadable')


def _completed(command, artifacts):
    return {'schema':ev.PREFIX+'command-result.v0','command':command,'status':'completed',
            'artifacts':[{'kind':kind,'sha256':ev.digest(raw)} for kind,raw in artifacts], 'reasons':[]},0


def plan_command(args):
    if args.reference_approval!='accept':
        ev.refuse('input','reference-rejected' if args.reference_approval=='reject' else 'reference-required')
    reference_raw=_read_input(args.reference)
    if ev.digest(reference_raw)!=args.reference_sha256:ev.refuse('input','reference-mismatch')
    basis=reader.load_assessment_basis(args.basis_dir)
    from aee_checker_sealed_run import assessment_execution_identity
    source=assessment_execution_identity(Path(args.root))
    snapshot=ev.build_assessment_plan(_read_input(args.proposal),reference_raw,basis,source)
    members=dict(snapshot);members.update(_plan_pins(members['plan.json'],args.root))
    _publish(members,args.out)
    return _completed('plan',[('plan',members['plan.json'])])


def _load_plan_stage(path, basis_dir, expected_path):
    members=dict(reader.load_package(path))
    retained=tuple(sorted((p,raw) for p,raw in members.items()
        if p in ('plan.json','proposal.json','reference.json') or '/corpus/' in p))
    pins={p:raw for p,raw in members.items() if '/pins/' in p}
    allowed={name+'/pins/'+pin for name in ev.VARIANTS
        for pin in ('control.json','sites.json','manifest.json','pins.json')}
    if set(members)!=set(p for p,_ in retained)|allowed:
        ev.refuse('filesystem','surplus-member')
    inputs=ev.AssessmentInputs(retained,reader.load_assessment_basis(basis_dir))
    gates,values=ev.evaluate_preflight(inputs)
    if values is None or any(g['status']!='passed' for g in gates):
        ev.refuse('replay','preflight-refused')
    expected_raw=reader.load_expected(expected_path)
    ev._require_expected_admission(ev.require_expected(expected_raw),values['plan'],
                                  values['execution']['plan_sha256'])
    return inputs,pins,values,expected_raw


def prepare_command(args):
    from aee_checker_sealed_run import assessment_execution_identity,prepare_owned_assessment_runtime
    from aee_checker_sealed_materialize import (materialize_owned_assessment,
        begin_atomic_dest,commit_atomic_dest,abort_atomic_dest)
    from aee_checker_sealed_common import PrepareError
    inputs,pins,values,expected=_load_plan_stage(args.plan_dir,args.basis_dir,args.expected)
    plan=values['plan']
    if assessment_execution_identity(_HERE.parent)!=plan['source']:
        ev.refuse('binding','source-identity')
    if args.variant not in ev.VARIANTS:ev.refuse('binding','plan-variant')
    # Check the supplied pinned metadata before any host observation.
    if pins != _plan_pins(dict(inputs.retained_members)['plan.json'],_HERE.parent):
        ev.refuse('binding','prepare-authorization')
    dest=Path(args.out)
    with reader._directory(reader._absolute_parts(dest)[:-1]):pass
    state=begin_atomic_dest(dest)
    try:
        mats=materialize_owned_assessment(args.inputs_dir,state['staging'],
            retained_members=inputs.retained_members,variant=args.variant,
            template=_HERE.parent/ev._OWNED.container_context_relpath/'cargo-config.toml')
        runtime=prepare_owned_assessment_runtime(image_id=args.image_id,materialized=mats)
        materialized={key:mats[key] for key in ('subject_tree_sha256','corpus_tree_sha256',
            'corpus_manifest_sha256','corpus_id_count','vendor_sha256','tool_sha256')}
        doc={'schema':ev.PREFIX+'prepare.v0','family':ev.FAMILY,
            'plan_sha256':values['execution']['plan_sha256'],'variant':args.variant,'profile':ev.PROFILE,
            'source':plan['source'],'pins_sha256':ev.digest(pins[args.variant+'/pins/pins.json']),
            'materialized':materialized,'runtime':runtime}
        raw=ev.encode(doc)
        # The shared runtime rules and actual tree checks precede publication.
        if len(raw)>65536:ev.refuse('limits','member-bytes')
        with (state['staging']/'prepare.json').open('xb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        commit_atomic_dest(state)
    except BaseException:
        abort_atomic_dest(state)
        raise
    return _completed('prepare',[('prepare',raw)])


def authorize_command(args):
    inputs,pins,values,expected=_load_plan_stage(args.plan_dir,args.basis_dir,args.expected)
    prepares={'base':_read_input(args.base_prepare),
              'outer-whitespace':_read_input(args.whitespace_prepare)}
    output=ev.build_assessment_authorization(inputs,pins,prepares,expected,args.operator)
    _publish(output,args.out)
    return _completed('authorize',[('authorization',output['authorization.json']),
        ('variant-authorization-base',output['base/authorization.json']),
        ('variant-authorization-outer-whitespace',output['outer-whitespace/authorization.json'])])


def finalize_command(args):
    snapshot=reader.load_package(args.assessment_dir)
    basis=reader.load_assessment_basis(args.basis_dir)
    stage=ev.decode_assessment_stage(snapshot,basis)
    expected_raw=reader.load_expected(args.expected)
    members=dict(snapshot);plan_hash=ev.digest(members['plan.json'])
    ev._require_expected_admission(ev.require_expected(expected_raw),stage['plan'],plan_hash)
    evaluation,issues=ev.replay_assessment_evidence(stage)
    if issues:
        stage_name,code,_=issues[0];ev.refuse(stage_name,code)
    review=None
    if args.review is not None:
        raw=_read_input(args.review)
        review=ev.decode(raw,canonical=True)
        members['review.json']=raw
    disposition=ev.derive_disposition(evaluation,stage['observations'],review,
        proposal_sha256=ev.digest(members['proposal.json']),
        evidence_index_sha256=ev.digest(members['evidence-index.json']))
    review_hash=ev.digest(members['review.json']) if review is not None else None
    decision={'schema':ev.PREFIX+'decision.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':ev.digest(members['evidence-index.json']),
        'gates_sha256':ev.digest(members['gates.json']),'review_sha256':review_hash,'disposition':disposition}
    members['decision.json']=ev.encode(decision)
    receipt={'schema':ev.PREFIX+'receipt.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':ev.digest(members['evidence-index.json']),
        'decision_sha256':ev.digest(members['decision.json']),'review_sha256':review_hash,
        'family':ev.FAMILY,'profile':ev.PROFILE,
        'source_content_sha256':stage['plan']['source']['content_sha256'],'origin':'producer-reported'}
    members['receipt.json']=ev.encode(receipt)
    expected=ev.require_expected(expected_raw)
    if expected['receipt_sha256'] is not None and expected['receipt_sha256']!=ev.digest(members['receipt.json']):
        ev.refuse('expectation','expected-identity-mismatch')
    complete=ev.decode_package(tuple(sorted(members.items())),basis)
    _,issues=ev.compare_package(complete)
    if issues:
        stage_name,code,_=issues[0];ev.refuse(stage_name,code)
    _publish(members,args.out)
    return _completed('finalize',[('receipt',members['receipt.json'])])


def _variant_contract(context):
    from sealed_measurement_contract import OwnedAssessmentVariantContract
    plan=ev.decode(dict(context.assessment_inputs.retained_members)['plan.json'])
    row=plan['variants'][ev.VARIANTS.index(context.variant)]
    return OwnedAssessmentVariantContract(ev.digest(dict(context.assessment_inputs.retained_members)['plan.json']),
        context.variant,row['manifest']['sha256'],row['tree_sha256'],tuple(v['id'] for v in row['vectors']))


class AssessmentRecorder:
    """Append and fsync start before entry; retain exact settled bytes once."""
    def __init__(self, stage, context):
        self.stage=Path(stage);self.context=context
        self.contract=_variant_contract(context)
        ev.require_assessment_context(context,context.profile,self.contract)
        self.plan=ev.decode(dict(context.assessment_inputs.retained_members)['plan.json'])
        self.plan_hash=ev.digest(dict(context.assessment_inputs.retained_members)['plan.json'])
        self.observations=[];self.views=[];self.events=[];self.next_slot=0
        self.members={};self.pending=None
        with (self.stage/'journal.jsonl').open('xb') as stream:
            stream.flush();os.fsync(stream.fileno())
        self._sync_directory(self.stage)

    @staticmethod
    def _sync_directory(path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def _write(self,path,doc):
        raw=ev.encode(doc)
        _,cap=ev.package_member_kind(path)
        if len(raw)>cap:ev.refuse('limits','member-bytes')
        dest=self.stage/path;dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self._sync_directory(dest.parent)
        self.members[path]=raw
        return ev.decode(raw,max_bytes=cap,canonical=True)

    def _event(self,slot,event,*,observation=None,reason=None):
        doc={'schema':ev.PREFIX+'journal-event.v0','seq':len(self.events),
            'plan_sha256':self.plan_hash,'slot':slot,'event':event,
            'observation':observation,'reason':reason}
        raw=ev.encode(doc)
        if len(raw)>2048 or len(self.events)>=32:ev.refuse('limits','journal-events')
        with (self.stage/'journal.jsonl').open('ab') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self.events.append(ev.decode(raw,canonical=True))

    def _envelope_ref(self,ledger,slot):
        import effective_envelope as envelope
        ordinal=slot['ordinal']
        entries=list(ledger.entries())
        if len(entries)<=ordinal or entries[ordinal][1]!='recorded':return None
        raw=envelope.encode_envelope(envelope.bind_report(entries[ordinal][2],None))
        if len(raw)>65536:ev.refuse('limits','member-bytes')
        return {'member':slot['variant']+'/envelopes/member-%04d.json'%ordinal,
                'sha256':ev.digest(raw),'bytes':len(raw)}

    def _settle(self,slot,doc):
        path=slot['variant']+'/observations/'+str(slot['ordinal'])+'.json'
        retained=self._write(path,doc)
        ref=ev._raw_ref(self.members,path)
        projection=ev.project_observation(retained,ids=self.contract.ids,plan_sha256=self.plan_hash)
        if retained['state']=='returned':
            view={'schema':ev.PREFIX+'view.v0','plan_sha256':self.plan_hash,'slot':slot,
                'observation':ref,'adapter_sha256':ev._OWNED.adapter_sha256,**projection}
            view_path=slot['variant']+'/views/'+str(slot['ordinal'])+'.json'
            self.views.append(self._write(view_path,view))
        self._event(slot,'returned' if retained['state']=='returned' else 'exception',
            observation=ref,reason=retained['exception_kind'])
        self.observations.append(retained);self.next_slot+=1;self.pending=None

    def wrap(self,inner,ledger,*,context=None):
        import corpus_adequacy as ca
        from suggestion_execution import _entry
        context=self.context if context is None else context
        contract=_variant_contract(context)
        ev.require_assessment_context(context,context.profile,contract)
        if (getattr(inner,ca.BACKEND_PROFILE_ATTRIBUTE,None)!=ev.PROFILE
                or getattr(inner,ca.BACKEND_STEP_ATTRIBUTE,None) is not True):
            ev.refuse('support','unsupported-profile')
        def wrapped(manifest,vectors,*,rebuild=True,step=None):
            ev.require_assessment_context(context,getattr(inner,ca.BACKEND_PROFILE_ATTRIBUTE,None),contract)
            if (getattr(inner,ca.BACKEND_STEP_ATTRIBUTE,None) is not True
                    or getattr(wrapped,ca.BACKEND_PROFILE_ATTRIBUTE,None)!=ev.PROFILE
                    or rebuild is not True or vectors is None or self.pending is not None
                    or self.next_slot>=8):
                ev.refuse('replay','schedule-mismatch')
            slot=self.plan['slots'][self.next_slot]
            if slot['variant']!=context.variant or step!=slot['step']:
                ev.refuse('replay','schedule-mismatch')
            self._event(slot,'started');self.pending=self.next_slot
            doc={'schema':ev.PREFIX+'observation.v0','plan_sha256':self.plan_hash,'slot':slot,
                'route':'contained-oci-v1-derived','profile':ev.PROFILE,'state':'exception',
                'raw':None,'sanitized_reason':None,'exception_kind':'backend-exception','envelope':None}
            try:
                result=inner(manifest,vectors,rebuild=True,step=step)
            except BaseException:
                doc['envelope']=self._envelope_ref(ledger,slot)
                self._settle(slot,doc)
                raise
            doc['envelope']=self._envelope_ref(ledger,slot)
            try:
                snapshot=ca._snapshot_process_execution(result)
                doc.update(state='returned',raw=_entry(step,snapshot),exception_kind=None)
                if snapshot.raised=={'<batch>':'unproved'}:
                    doc['sanitized_reason']=ca.sanitize_unproved_reason(snapshot.detail)
                # Encode/decode before judging, matching the bytes that will be retained.
                doc=ev.decode(ev.encode(doc),max_bytes=1048576,canonical=True)
                ev.project_observation(doc,ids=contract.ids,plan_sha256=self.plan_hash)
            except Exception as invalid:
                kind='observation-budget' if isinstance(invalid,ev.EvidenceError) and invalid.stage=='limits' else 'invalid-backend-result'
                doc.update(state='invalid-return',raw=None,sanitized_reason=None,exception_kind=kind)
                self._settle(slot,doc)
                ev.refuse('execution','assessment-unproved')
            self._settle(slot,doc)
            return result
        setattr(wrapped,ca.BACKEND_PROFILE_ATTRIBUTE,ev.PROFILE)
        setattr(wrapped,ca.BACKEND_STEP_ATTRIBUTE,True)
        return wrapped

    def stop_remaining(self,*,preflight=False):
        if self.pending is not None:ev.refuse('journal','unsettled-attempt')
        while self.next_slot<8:
            self._event(self.plan['slots'][self.next_slot],
                'preflight-refused' if preflight else 'not-started',
                reason='preflight-refusal' if preflight else 'prerequisite-refused')
            self.next_slot+=1;preflight=False


def dispatch(args):
    if args.command=='plan':return plan_command(args)
    if args.command=='authorize':return authorize_command(args)
    if args.command=='prepare':return prepare_command(args)
    if args.command=='finalize':return finalize_command(args)
    ev.refuse('input','internal-error')


if __name__ == '__main__':
    raise SystemExit(main())
