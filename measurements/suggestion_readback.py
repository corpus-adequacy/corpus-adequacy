"""Bounded external input loaders for owned assessment (#224).

Offline verification only: no candidate execution, network or subprocesses.
The caller explicitly selects the original-basis directory and expected file.
Only immutable snapshots leave this filesystem boundary; they grant no consent.
"""
from contextlib import contextmanager, ExitStack
import os
import stat
import sys

# Trusted installed source root only; never derive import paths from package data.
if __package__ in (None, ""):
    sys.path[:0] = [os.path.dirname(os.path.abspath(__file__)),
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]

import suggestion_evidence as ev

MEMBER_BYTES = 65536
BASIS_TOTAL_BYTES = 393216
_VECTOR_NAMES = frozenset(p.split('/', 1)[1] for p in ev.BASIS_PATHS if p.startswith('vectors/'))


def _require_support():
    if (not all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'))
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks
            or os.scandir not in os.supports_fd):
        ev.refuse('support', 'unsupported-filesystem')


def _signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _stat_at(parent, name):
    return os.stat(name, dir_fd=parent, follow_symlinks=False)


def _assert_same(before, after):
    if _signature(before) != _signature(after):
        ev.refuse('filesystem', 'nonregular-member')


@contextmanager
def _child(parent, name, *, directory, ancestor=False):
    """Open one component and detect replacement between stat and open/close."""
    def same(before, after):
        if ancestor:
            # Sibling writes change directory times/size/link count, not the
            # selected path identity. Retain replacement/type/owner/mode checks.
            identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)
            if identity(before)!=identity(after):
                ev.refuse('filesystem','nonregular-member')
        else:
            _assert_same(before,after)
    before = _stat_at(parent, name)
    check = stat.S_ISDIR if directory else stat.S_ISREG
    if not check(before.st_mode) or (not directory and before.st_nlink != 1):
        ev.refuse('filesystem', 'nonregular-member')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        if not check(opened.st_mode) or (not directory and opened.st_nlink != 1):
            ev.refuse('filesystem', 'nonregular-member')
        same(before, opened)
        yield fd
        same(opened, os.fstat(fd))
        same(opened, _stat_at(parent, name))
    finally:
        os.close(fd)


def _absolute_parts(path):
    value = os.fspath(path)
    if type(value) is not str or not value or '\x00' in value or '\\' in value:
        ev.refuse('input', 'argument-invalid')
    if '..' in value.split('/'):
        ev.refuse('filesystem', 'unsafe-member')
    # No resolve()/realpath(): following an ancestor link is not a safe-open.
    return tuple(p for p in os.path.abspath(value).split('/') if p)


@contextmanager
def _directory(parts):
    """Walk from filesystem root, keeping each open independent of later links."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with ExitStack() as stack:
            current = fd
            for index,part in enumerate(parts):
                current = stack.enter_context(_child(current, part, directory=True,
                    ancestor=index<len(parts)-1))
            yield current
    finally:
        os.close(fd)


def _inventory(fd, expected):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > len(expected):
                ev.refuse('filesystem', 'surplus-member')
    if len(names) != len(set(n.casefold() for n in names)):
        ev.refuse('filesystem', 'duplicate-member')
    if set(names) != set(expected):
        ev.refuse('filesystem', 'surplus-member' if set(names) - set(expected) else 'missing-member')


def _read_file(parent, name, *, remaining, seen, cap=MEMBER_BYTES, budget_code="aggregate-bytes"):
    with _child(parent, name, directory=False) as fd:
        st = os.fstat(fd)
        identity = (st.st_dev, st.st_ino)
        if identity in seen:
            ev.refuse('filesystem', 'duplicate-member')
        seen.add(identity)
        if st.st_size > cap:
            ev.refuse('limits', 'member-bytes')
        if st.st_size > remaining:
            ev.refuse('limits', budget_code)
        limit = min(cap, remaining)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(16384, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                ev.refuse('limits', 'member-bytes' if limit == cap else budget_code)
            chunks.append(chunk)
        return b''.join(chunks)


def _load_basis_snapshot(path):
    """Snapshot the exact original LICENSE+vectors tree without semantic claims."""
    _require_support()
    parts = _absolute_parts(path)
    try:
        with _directory(parts) as root:
            original = os.fstat(root)
            _inventory(root, ('LICENSE', 'vectors'))
            seen = set()
            license_raw = _read_file(root, 'LICENSE', remaining=BASIS_TOTAL_BYTES, seen=seen)
            snapshot = [('LICENSE', license_raw)]
            total = len(license_raw)
            with _child(root, 'vectors', directory=True) as vectors:
                _inventory(vectors, _VECTOR_NAMES)
                for name in sorted(_VECTOR_NAMES):
                    raw = _read_file(vectors, name, remaining=BASIS_TOTAL_BYTES-total, seen=seen)
                    total += len(raw)
                    snapshot.append(('vectors/'+name, raw))
                _inventory(vectors, _VECTOR_NAMES)
            _inventory(root, ('LICENSE', 'vectors'))
            _assert_same(original, os.fstat(root))
        snapshot = tuple(sorted(snapshot))
        return snapshot
    except OSError:
        ev.refuse('filesystem', 'unreadable')


def load_assessment_basis(path):
    """Snapshot exact original LICENSE+vectors tree and check installed oracle."""
    snapshot = _load_basis_snapshot(path)
    ev.require_basis(snapshot)
    return snapshot


def load_expected(path):
    """Read caller-selected external expected bytes; never create expectations."""
    _require_support()
    parts = _absolute_parts(path)
    if not parts:
        ev.refuse('input', 'argument-invalid')
    try:
        with _directory(parts[:-1]) as parent:
            raw = _read_file(parent, parts[-1], remaining=MEMBER_BYTES, seen=set())
        ev.require_expected(raw)
        return raw
    except OSError:
        ev.refuse('filesystem', 'unreadable')


def _result():
    return {'schema': ev.PREFIX+'reader-result.v0', 'load': 'invalid',
            'internal_consistency': 'not-evaluated', 'expected_identity': 'not-evaluated',
            'reference_approval': 'not-evaluated', 'replay_disposition': 'not-evaluated',
            'origin': 'unverified', 'reasons': []}


def main(argv=None):
    """Bounded machine error boundary; argument errors never escape as argparse prose."""
    import argparse
    import sys

    class Parser(argparse.ArgumentParser):
        def error(self, message):
            ev.refuse('input', 'argument-invalid')

    result = _result()
    try:
        parser = Parser(prog='suggestion_readback')
        sub = parser.add_subparsers(dest='command', required=True)
        verify = sub.add_parser('verify')
        verify.add_argument('--package', required=True)
        verify.add_argument('--basis-dir', required=True)
        expected = verify.add_mutually_exclusive_group()
        expected.add_argument('--expected')
        expected.add_argument('--unanchored', action='store_true')
        verify.add_argument('--mode', choices=('handoff', 'audit'), default='handoff')
        args = parser.parse_args(argv)
        if not args.expected and (args.mode == 'handoff' or not args.unanchored):
            ev.refuse('input', 'expected-required')
        result, code = verify_package(args.package, args.basis_dir, expected=args.expected, mode=args.mode)
    except ev.EvidenceError as exc:
        result['reasons'] = [{'stage': exc.stage, 'code': exc.code, 'member': None}]
        code = 2
    except Exception:
        result['reasons'] = [{'stage': 'input', 'code': 'internal-error', 'member': None}]
        code = 2
    sys.stdout.buffer.write(ev.encode(result))
    return code



PACKAGE_BYTES = 31522816
PACKAGE_FILES = 128
PACKAGE_DIRECTORIES = 32
PACKAGE_DEPTH = 6
CATEGORY_BYTES = {'envelopes':10485760, 'observations':8388608, 'views':8388608,
                  'corpora':2097152, 'metadata':2097152, 'journal':65536}
CATEGORY_COUNTS = {'envelopes':10, 'observations':8, 'views':8, 'corpora':12,
                   'metadata':32, 'journal':1}


def load_package(path):
    """One no-follow, bounded raw snapshot; all later passes reuse these bytes."""
    _require_support()
    snapshot, directories, seen = [], set(), set()
    totals={kind:0 for kind in CATEGORY_BYTES};counts=dict.fromkeys(totals,0)
    aggregate=0

    def inventory(fd):
        names=[]
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names)>PACKAGE_FILES+PACKAGE_DIRECTORIES: ev.refuse('limits','entry-count')
        if len(set(n.casefold() for n in names))!=len(names): ev.refuse('filesystem','duplicate-member')
        return sorted(names)

    def walk(fd,prefix=''):
        nonlocal aggregate
        before=os.fstat(fd);names=inventory(fd)
        for name in names:
            member=prefix+name
            if ('\\' in name or name in ('.','..') or len(member.encode('utf-8',errors='surrogatepass'))>192):
                ev.refuse('filesystem','unsafe-member')
            if len(member.split('/'))>PACKAGE_DEPTH: ev.refuse('limits','path-depth')
            if member in ev.PACKAGE_DIRS:
                directories.add(member)
                if len(directories)>PACKAGE_DIRECTORIES: ev.refuse('limits','entry-count')
                with _child(fd,name,directory=True) as child: walk(child,member+'/')
                continue
            kind,cap=ev.package_member_kind(member)
            if len(snapshot)>=PACKAGE_FILES or counts[kind]>=CATEGORY_COUNTS[kind]: ev.refuse('limits','entry-count')
            category_remaining=CATEGORY_BYTES[kind]-totals[kind]
            remaining=PACKAGE_BYTES-aggregate
            budget_code='aggregate-bytes'
            if category_remaining<remaining: remaining=category_remaining;budget_code='category-bytes'
            raw=_read_file(fd,name,remaining=remaining,seen=seen,cap=cap,budget_code=budget_code)
            aggregate+=len(raw);totals[kind]+=len(raw);counts[kind]+=1
            snapshot.append((member,raw))
        if inventory(fd)!=names: ev.refuse('filesystem','nonregular-member')
        _assert_same(before,os.fstat(fd))

    try:
        with _directory(_absolute_parts(path)) as root: walk(root)
    except FileNotFoundError: ev.refuse('filesystem','missing-member')
    except OSError: ev.refuse('filesystem','unreadable')
    actual_dirs={'/'.join(p.split('/')[:i]) for p,_ in snapshot for i in range(1,len(p.split('/')))}
    if directories!=actual_dirs: ev.refuse('filesystem','surplus-member')
    return tuple(sorted(snapshot))


_STAGE_ORDER = ('input','filesystem','limits','syntax','support','journal','binding','replay','envelope','expectation','result')


def _reasons(issues):
    rows=sorted(set(issues),key=lambda r:(_STAGE_ORDER.index(r[0]),(r[2] or '').encode(),r[1]))
    if len(rows)>32: rows=rows[:31]+[('result','reasons-truncated',None)]
    return [{'stage':stage,'code':code,'member':member} for stage,code,member in rows]


def _error_result(result,exc):
    result['reasons']=_reasons([(r['stage'],r['code'],r['member']) for r in result['reasons']]+[(exc.stage,exc.code,None)])
    semantic = exc.stage in ('binding','expectation') or (exc.stage=='replay' and exc.code!='schedule-mismatch')
    if semantic:
        result['load']='complete'
        if exc.stage!='expectation':result['internal_consistency']='mismatch'
        return result,1
    result['load']=('unsupported' if exc.stage=='support' else
        'incomplete' if exc.stage=='journal' or (exc.stage=='filesystem' and exc.code=='missing-member') else 'invalid')
    return result,2


def verify_package(path, basis_path, *, expected=None, mode='handoff'):
    result=_result()
    try:
        if mode not in ('audit','handoff'): ev.refuse('input','argument-invalid')
        if expected is None and mode=='handoff':ev.refuse('input','expected-required')
        try:
            expectation=ev.require_expected(load_expected(expected)) if expected is not None else None
        except ev.EvidenceError as exc:
            if exc.stage in ('syntax','binding','input'): ev.refuse('input','expected-invalid')
            raise
        if mode=='handoff' and expectation['reference_approval']!='accept':
            ev.refuse('input','reference-rejected' if expectation['reference_approval']=='reject' else 'reference-required')
        snapshot=load_package(path)
        basis=_load_basis_snapshot(basis_path)
        package=ev.decode_package(snapshot,basis)
        result['load']='complete'
        issues=[]
        if expectation is None:
            result['expected_identity']=result['reference_approval']='not-supplied'
        else:
            plan=package['plan'];members=package['members']
            matches=(expectation['plan_sha256']==ev.digest(members['plan.json'])
                and expectation['source_content_sha256']==plan['source']['content_sha256']
                and expectation['source_files']==plan['source']['files']
                and expectation['reference_sha256']==ev.digest(members['reference.json'])
                and expectation['policy']==plan['policy']
                and (expectation['receipt_sha256'] is None or expectation['receipt_sha256']==ev.digest(members['receipt.json'])))
            result['expected_identity']='match' if matches else 'mismatch'
            approval=expectation['reference_approval']
            result['reference_approval']='not-supplied' if approval=='unavailable' else approval
            if not matches:issues.append(('expectation','expected-identity-mismatch',None))
            if approval=='reject':issues.append(('expectation','reference-rejected',None))
            result['reasons']=_reasons(issues)
            if mode=='handoff' and not matches:return result,1
        disposition,internal=ev.compare_package(package)
        result['internal_consistency']='mismatch' if internal else 'match'
        result['replay_disposition']=disposition
        result['reasons']=_reasons(issues+internal)
        return result,1 if result['reasons'] else 0
    except ev.EvidenceError as exc:
        return _error_result(result,exc)


if __name__ == '__main__':
    raise SystemExit(main())
