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


def authorize_command(args):
    inputs,pins,values,expected=_load_plan_stage(args.plan_dir,args.basis_dir,args.expected)
    prepares={'base':_read_input(args.base_prepare),
              'outer-whitespace':_read_input(args.whitespace_prepare)}
    output=ev.build_assessment_authorization(inputs,pins,prepares,expected,args.operator)
    _publish(output,args.out)
    return _completed('authorize',[('authorization',output['authorization.json']),
        ('variant-authorization-base',output['base/authorization.json']),
        ('variant-authorization-outer-whitespace',output['outer-whitespace/authorization.json'])])


def dispatch(args):
    if args.command=='plan':return plan_command(args)
    if args.command=='authorize':return authorize_command(args)
    ev.refuse('input','internal-error')


if __name__ == '__main__':
    raise SystemExit(main())
