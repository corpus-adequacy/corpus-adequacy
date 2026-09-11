#!/usr/bin/env python3
"""Hosted packet delivery (#107): fetch an owner-published packet by manifest digest.

RED-first. The network layer is a fake keyed by the exact release-asset URL, so no test reaches
the network, Docker, a candidate or a score. Every refusal is asserted by name, and each one is
asserted to happen before a later step: no asset fetched after a manifest refusal, nothing
written after any refusal.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import hosted_packet as packet  # noqa: E402

REPOSITORY = "corpus-adequacy/corpus-adequacy"
TAG = "hosted-packet-r1"
PINS_SOURCE = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
SHA_A = "a" * 40
SHA_B = "b" * 40


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git_env() -> dict:
    # A hook or an outer git process may export GIT_DIR/GIT_INDEX_FILE; the temp repository
    # must never be resolved through them.
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _workspace(tmp: Path) -> Path:
    """A checked-out tree in miniature: a git work tree carrying R's pins directory."""
    ws = tmp / "ws"
    ws.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=ws, check=True, capture_output=True,
                   env=_git_env())
    pins = ws / "measurements" / "aee-checker-25b9dfa"
    pins.mkdir(parents=True)
    for name in sorted(os.listdir(PINS_SOURCE)):
        shutil.copyfile(PINS_SOURCE / name, pins / name)
    return ws


def _files() -> dict:
    return {
        packet.AUTHORIZE_FILENAME: b'{"phase": "authorize"}\n',
        packet.BINDINGS_FILENAME: b'{"runner_revision": "%s"}\n' % SHA_B.encode("ascii"),
        packet.PREPARE_FILENAME: b'{"phase": "prepare"}\n',
    }


def _manifest_raw(files: dict, *, schema=None, extra=None) -> bytes:
    doc = {
        "files": {name: _sha256(raw) for name, raw in files.items()},
        "schema": packet.MANIFEST_SCHEMA if schema is None else schema,
    }
    if extra:
        doc.update(extra)
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


class FakeRelease:
    """Serves assets of one release by exact URL and records every request in order.

    It returns whatever bytes it holds regardless of the requested ceiling, so the ceiling
    under test is the module's own, not the fake's.
    """

    def __init__(self, assets: dict, *, repository=REPOSITORY, tag=TAG, on_fetch=None):
        self.assets = dict(assets)
        self.prefix = "https://github.com/%s/releases/download/%s/" % (repository, tag)
        self.calls = []
        self.on_fetch = on_fetch

    def __call__(self, url, max_bytes):
        self.calls.append((url, max_bytes))
        if not url.startswith(self.prefix):
            raise AssertionError("unexpected url %r" % url)
        name = urllib.parse.unquote(url[len(self.prefix):])
        if self.on_fetch is not None:
            self.on_fetch(name)
        if name not in self.assets:
            raise packet.PacketError("fetch_failed")
        return self.assets[name]

    def names(self):
        return [urllib.parse.unquote(url[len(self.prefix):]) for url, _ in self.calls]


def _release(files=None, manifest_raw=None):
    files = _files() if files is None else files
    raw = _manifest_raw(files) if manifest_raw is None else manifest_raw
    return FakeRelease({packet.MANIFEST_FILENAME: raw, **files}), _sha256(raw)


def _snapshot(ws: Path, *, exclude: str) -> dict:
    """Every file outside `exclude` and `.git`, with its digest, to prove nothing else moved."""
    seen = {}
    for dirpath, dirnames, filenames in os.walk(ws):
        if Path(dirpath) == ws:
            dirnames[:] = [d for d in dirnames if d not in (exclude, ".git")]
        for name in filenames:
            path = Path(dirpath) / name
            seen[str(path.relative_to(ws))] = _sha256(path.read_bytes())
    return seen


def _fetch(ws, fake, sha, *, dest=packet.PACKET_DIRNAME, **kwargs):
    return packet.fetch_packet(
        repository=REPOSITORY, tag=TAG, manifest_sha256=sha,
        workspace_root=ws, dest=dest, open_url=fake, **kwargs)


class FetchAcceptsTheBoundPacket(unittest.TestCase):
    def test_fetch_writes_exactly_the_bound_files_and_pins_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            before = _snapshot(ws, exclude=packet.PACKET_DIRNAME)
            fake, sha = _release()
            result = _fetch(ws, fake, sha)
            dest = ws / packet.PACKET_DIRNAME
            self.assertEqual(result["manifest_sha256"], sha)
            # Manifest first, then each listed asset individually; no archive, no listing.
            self.assertEqual(fake.names(), [packet.MANIFEST_FILENAME, *packet.PACKET_FILENAMES])
            for url, cap in fake.calls:
                self.assertTrue(url.startswith("https://"), url)
                self.assertIn(cap, (packet.MAX_MANIFEST_BYTES, packet.MAX_FILE_BYTES))
            self.assertEqual(
                sorted(os.listdir(dest)),
                sorted([packet.MANIFEST_FILENAME, packet.PINS_DIRNAME, *packet.PACKET_FILENAMES]))
            self.assertEqual((dest / packet.MANIFEST_FILENAME).read_bytes(),
                             fake.assets[packet.MANIFEST_FILENAME])
            for name, body in _files().items():
                self.assertEqual((dest / name).read_bytes(), body)
            # Pins come from the checked-out tree, byte for byte, never from the release.
            pins = dest / packet.PINS_DIRNAME
            self.assertEqual(sorted(os.listdir(pins)), sorted(os.listdir(PINS_SOURCE)))
            for name in os.listdir(PINS_SOURCE):
                self.assertEqual((pins / name).read_bytes(), (PINS_SOURCE / name).read_bytes())
            self.assertEqual(_snapshot(ws, exclude=packet.PACKET_DIRNAME), before,
                             "fetch wrote outside its destination")

    def test_verify_manifest_digest_before_parse_with_unparseable_bytes(self):
        """A manifest that is not even JSON is refused for its digest, not for its syntax."""
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            fake, _sha = _release(manifest_raw=b"{not json")
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, "0" * 64)
            self.assertEqual(str(ctx.exception), "manifest_digest")
            self.assertEqual(fake.names(), [packet.MANIFEST_FILENAME])
            self.assertFalse(os.path.lexists(ws / packet.PACKET_DIRNAME))


class FetchRefusesBeforeTheNextStep(unittest.TestCase):
    def _refused(self, fake, sha, reason, *, fetched=None, **kwargs):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            before = _snapshot(ws, exclude=packet.PACKET_DIRNAME)
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha, **kwargs)
            self.assertEqual(str(ctx.exception), reason)
            if fetched is not None:
                self.assertEqual(fake.names(), fetched)
            self.assertFalse(os.path.lexists(ws / packet.PACKET_DIRNAME),
                             "a refused fetch created its destination")
            self.assertEqual(_snapshot(ws, exclude=packet.PACKET_DIRNAME), before)

    def test_manifest_digest_mismatch_refuses_before_any_asset(self):
        fake, sha = _release()
        wrong = _sha256(b"another manifest")
        self._refused(fake, wrong, "manifest_digest", fetched=[packet.MANIFEST_FILENAME])
        self.assertNotEqual(wrong, sha)

    def test_per_file_digest_mismatch_refuses(self):
        fake, sha = _release()
        fake.assets[packet.PREPARE_FILENAME] = b'{"phase": "tampered"}\n'
        self._refused(fake, sha, "file_digest")

    def test_oversize_file_refuses_under_the_module_ceiling(self):
        files = _files()
        files[packet.PREPARE_FILENAME] = b"x" * 65
        fake, sha = _release(files)
        self._refused(fake, sha, "file_oversize", max_file_bytes=64)

    def test_oversize_manifest_refuses_before_its_digest_is_used(self):
        files = _files()
        raw = _manifest_raw(files, extra=None) + b" " * 40
        fake, sha = _release(files, manifest_raw=raw)
        self._refused(fake, sha, "manifest_oversize", fetched=[packet.MANIFEST_FILENAME],
                      max_manifest_bytes=len(raw) - 1)

    def test_duplicate_manifest_key_refuses(self):
        files = _files()
        digests = {name: _sha256(body) for name, body in files.items()}
        for text in (
            # Duplicate inside `files`: a later entry would silently replace the first digest.
            '{"files": {"%s": "%s", "%s": "%s", "%s": "%s", "%s": "%s"}, "schema": "%s"}' % (
                packet.AUTHORIZE_FILENAME, "0" * 64,
                packet.AUTHORIZE_FILENAME, digests[packet.AUTHORIZE_FILENAME],
                packet.BINDINGS_FILENAME, digests[packet.BINDINGS_FILENAME],
                packet.PREPARE_FILENAME, digests[packet.PREPARE_FILENAME],
                packet.MANIFEST_SCHEMA),
            # Duplicate at the top level.
            '{"files": {}, "files": %s, "schema": "%s"}' % (
                json.dumps(digests), packet.MANIFEST_SCHEMA),
        ):
            raw = text.encode("utf-8")
            fake, sha = _release(files, manifest_raw=raw)
            self._refused(fake, sha, "manifest_duplicate_key",
                          fetched=[packet.MANIFEST_FILENAME])

    def test_unsafe_names_refuse_by_name_before_any_asset(self):
        cases = (
            ("../" + packet.AUTHORIZE_FILENAME, "manifest_name_dotdot"),
            ("..", "manifest_name_dotdot"),
            ("a..b", "manifest_name_dotdot"),
            ("/etc/passwd", "manifest_name_absolute"),
            ("C:\\authorize.v0.json", "manifest_name_absolute"),
            ("C:authorize.v0.json", "manifest_name_absolute"),
            ("sub/" + packet.PREPARE_FILENAME, "manifest_name_separator"),
            ("sub\\" + packet.PREPARE_FILENAME, "manifest_name_separator"),
            ("prepare\x00.json", "manifest_name_control"),
            (".", "manifest_name_escapes"),
            ("", "manifest_name_type"),
        )
        for name, reason in cases:
            with self.subTest(name=name):
                files = _files()
                body = files.pop(packet.AUTHORIZE_FILENAME)
                digests = {n: _sha256(b) for n, b in files.items()}
                digests[name] = _sha256(body)
                raw = (json.dumps({"files": digests, "schema": packet.MANIFEST_SCHEMA},
                                  sort_keys=True) + "\n").encode("utf-8")
                fake, sha = _release(files, manifest_raw=raw)
                self._refused(fake, sha, reason, fetched=[packet.MANIFEST_FILENAME])

    def test_extra_missing_and_malformed_manifest_entries_refuse(self):
        files = _files()
        digests = {n: _sha256(b) for n, b in files.items()}
        cases = (
            ({"files": {**digests, "extra.json": "0" * 64},
              "schema": packet.MANIFEST_SCHEMA}, "manifest_name_unknown"),
            ({"files": {n: d for n, d in digests.items()
                        if n != packet.AUTHORIZE_FILENAME},
              "schema": packet.MANIFEST_SCHEMA}, "manifest_files_incomplete"),
            ({"files": digests, "schema": packet.MANIFEST_SCHEMA, "note": "x"},
             "manifest_keys"),
            ({"files": digests}, "manifest_keys"),
            ({"files": digests, "schema": "other"}, "manifest_schema"),
            ({"files": [digests], "schema": packet.MANIFEST_SCHEMA}, "manifest_files"),
            ({"files": {**digests, packet.PREPARE_FILENAME: "F" * 64},
              "schema": packet.MANIFEST_SCHEMA}, "manifest_file_digest"),
            ([digests], "manifest_keys"),
        )
        for doc, reason in cases:
            with self.subTest(reason=reason, doc=doc):
                raw = (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")
                fake, sha = _release(files, manifest_raw=raw)
                self._refused(fake, sha, reason, fetched=[packet.MANIFEST_FILENAME])

    def test_fetcher_returning_non_bytes_refuses(self):
        fake, sha = _release()
        fake.assets[packet.BINDINGS_FILENAME] = "not-bytes"
        self._refused(fake, sha, "fetch_failed")


class DestinationMustBeFresh(unittest.TestCase):
    def test_existing_destination_refuses_before_any_fetch(self):
        for kind in ("dir", "file", "dangling-symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as raw:
                ws = _workspace(Path(raw))
                dest = ws / packet.PACKET_DIRNAME
                if kind == "dir":
                    dest.mkdir()
                elif kind == "file":
                    dest.write_bytes(b"x")
                else:
                    dest.symlink_to(Path(raw) / "nowhere")
                fake, sha = _release()
                with self.assertRaises(packet.PacketError) as ctx:
                    _fetch(ws, fake, sha)
                self.assertEqual(str(ctx.exception), "destination_exists")
                self.assertEqual(fake.calls, [], "refusal must precede every network call")

    def test_destination_tracked_in_the_checkout_refuses_even_when_absent_on_disk(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            tracked = ws / packet.PACKET_DIRNAME / packet.PREPARE_FILENAME
            tracked.parent.mkdir()
            tracked.write_bytes(b"tracked\n")
            subprocess.run(["git", "add", "--", str(tracked.relative_to(ws))], cwd=ws,
                           check=True, capture_output=True, env=_git_env())
            shutil.rmtree(tracked.parent)
            fake, sha = _release()
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha)
            self.assertEqual(str(ctx.exception), "destination_tracked")
            self.assertEqual(fake.calls, [])
            self.assertFalse(os.path.lexists(ws / packet.PACKET_DIRNAME))

    def test_workspace_outside_a_git_checkout_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = Path(raw) / "plain"
            ws.mkdir()
            fake, sha = _release()
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha)
            self.assertEqual(str(ctx.exception), "checkout_unreadable")
            self.assertEqual(fake.calls, [])

    def test_destination_must_be_one_safe_component(self):
        for dest in ("../escape", "/abs", "a/b", "a\\b", "..", ".", "", None):
            with self.subTest(dest=dest), tempfile.TemporaryDirectory() as raw:
                ws = _workspace(Path(raw))
                fake, sha = _release()
                with self.assertRaises(packet.PacketError) as ctx:
                    _fetch(ws, fake, sha, dest=dest)
                self.assertEqual(str(ctx.exception), "destination_path")
                self.assertEqual(fake.calls, [])

    def test_symlinked_workspace_root_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            link = Path(raw) / "ws-link"
            link.symlink_to(ws)
            fake, sha = _release()
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(link, fake, sha)
            self.assertEqual(str(ctx.exception), "workspace_root")
            self.assertEqual(fake.calls, [])

    def test_destination_planted_as_symlink_mid_fetch_is_not_followed(self):
        """The early check is not the only one: a destination that appears during the network
        phase (here a symlink to a directory outside the workspace) refuses at creation, and
        nothing lands behind the link."""
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            outside = Path(raw) / "outside"
            outside.mkdir()

            def plant(name):
                if name == packet.PACKET_FILENAMES[-1]:
                    (ws / packet.PACKET_DIRNAME).symlink_to(outside)

            fake, sha = _release()
            fake.on_fetch = plant
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha)
            self.assertEqual(str(ctx.exception), "destination_exists")
            self.assertEqual(os.listdir(outside), [])

    def test_new_file_write_refuses_an_existing_symlink(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            target = base / "target"
            target.write_bytes(b"original")
            link = base / "link"
            link.symlink_to(target)
            with self.assertRaises(packet.PacketError) as ctx:
                packet.write_new_regular_file(link, b"overwrite")
            self.assertEqual(str(ctx.exception), "file_exists")
            self.assertEqual(target.read_bytes(), b"original")


class PinsComeFromTheCheckedOutTree(unittest.TestCase):
    def test_symlink_in_pins_source_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            src = ws / "measurements" / "aee-checker-25b9dfa"
            secret = Path(raw) / "secret.json"
            secret.write_bytes(b"{}\n")
            (src / "sites.json").unlink()
            (src / "sites.json").symlink_to(secret)
            fake, sha = _release()
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha)
            self.assertEqual(str(ctx.exception), "pins_source_entry")
            self.assertFalse(os.path.lexists(ws / packet.PACKET_DIRNAME))

    def test_missing_pins_source_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            shutil.rmtree(ws / "measurements" / "aee-checker-25b9dfa")
            fake, sha = _release()
            with self.assertRaises(packet.PacketError) as ctx:
                _fetch(ws, fake, sha)
            self.assertEqual(str(ctx.exception), "pins_source")
            self.assertFalse(os.path.lexists(ws / packet.PACKET_DIRNAME))


class InputsAndNetworkLayer(unittest.TestCase):
    def test_repository_tag_and_digest_inputs_refuse_before_any_fetch(self):
        cases = (
            ({"repository": "a/b/c"}, "repository"),
            ({"repository": "../x"}, "repository"),
            ({"repository": "owner/.."}, "repository"),
            ({"tag": "v1/../x"}, "tag"),
            ({"tag": ".."}, "tag"),
            ({"tag": ""}, "tag"),
            ({"manifest_sha256": "A" * 64}, "manifest_sha256"),
            ({"manifest_sha256": "a" * 63}, "manifest_sha256"),
        )
        for over, reason in cases:
            with self.subTest(over=over), tempfile.TemporaryDirectory() as raw:
                ws = _workspace(Path(raw))
                fake, sha = _release()
                kwargs = {"repository": REPOSITORY, "tag": TAG, "manifest_sha256": sha,
                          "workspace_root": ws, "dest": packet.PACKET_DIRNAME,
                          "open_url": fake}
                kwargs.update(over)
                with self.assertRaises(packet.PacketError) as ctx:
                    packet.fetch_packet(**kwargs)
                self.assertEqual(str(ctx.exception), reason)
                self.assertEqual(fake.calls, [])

    def test_release_asset_url_is_https_and_quotes_each_segment(self):
        url = packet.release_asset_url(REPOSITORY, TAG, packet.PREPARE_FILENAME)
        self.assertEqual(
            url, "https://github.com/%s/releases/download/%s/%s"
            % (REPOSITORY, TAG, packet.PREPARE_FILENAME))

    def test_default_open_url_refuses_non_https_without_touching_the_network(self):
        for url in ("http://github.com/x", "file:///etc/passwd", "ftp://x/y"):
            with self.subTest(url=url):
                with self.assertRaises(packet.PacketError) as ctx:
                    packet.default_open_url(url, 16)
                self.assertEqual(str(ctx.exception), "fetch_scheme")

    def test_default_open_url_refuses_a_host_other_than_github_before_the_network(self):
        with mock.patch.object(packet.urllib.request, "build_opener",
                               side_effect=AssertionError("network reached")) as opener:
            for url in ("https://evil.example/x", "https://github.com.evil.example/x",
                        "https://user@github.com/x", "https://github.com:8443/x"):
                with self.subTest(url=url):
                    with self.assertRaises(packet.PacketError) as ctx:
                        packet.default_open_url(url, 16)
                    self.assertEqual(str(ctx.exception), "fetch_host")
        opener.assert_not_called()

    def test_redirects_are_followed_only_to_the_documented_release_asset_host(self):
        """GitHub's hosted-runner docs name release-assets.githubusercontent.com as the host
        needed for downloading release assets; the digest binds the bytes, the pin bounds
        where the runner is sent."""
        import urllib.request
        handler = packet._PinnedRedirect()
        req = urllib.request.Request("https://github.com/o/r/releases/download/t/f")
        ok = "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?x=y"
        self.assertIsNotNone(handler.redirect_request(req, None, 302, "Found", {}, ok))
        for bad, reason in (
                ("http://release-assets.githubusercontent.com/a", "fetch_redirect_scheme"),
                ("https://objects.githubusercontent.com/a", "fetch_redirect_host"),
                ("https://release-assets.githubusercontent.com.evil.example/a",
                 "fetch_redirect_host"),
                ("https://evil.example/release-assets.githubusercontent.com",
                 "fetch_redirect_host"),
                ("https://user@release-assets.githubusercontent.com/a", "fetch_redirect_host"),
                ("https://release-assets.githubusercontent.com:8443/a", "fetch_redirect_host")):
            with self.subTest(bad=bad):
                with self.assertRaises(packet.PacketError) as ctx:
                    handler.redirect_request(req, None, 302, "Found", {}, bad)
                self.assertEqual(str(ctx.exception), reason)
        self.assertLessEqual(packet._PinnedRedirect.max_redirections, 2)

    def test_the_final_url_must_be_github_or_the_release_asset_host(self):
        class Response:
            status = 200
            headers = {}

            def __init__(self, final):
                self.final = final

            def geturl(self):
                return self.final

            def read(self, _n):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        for final, reason in (("https://evil.example/a", "fetch_redirect_host"),
                              ("http://release-assets.githubusercontent.com/a",
                               "fetch_redirect_scheme")):
            with self.subTest(final=final):
                opener = mock.Mock()
                opener.open.return_value = Response(final)
                with mock.patch.object(packet.urllib.request, "build_opener",
                                       return_value=opener):
                    with self.assertRaises(packet.PacketError) as ctx:
                        packet.default_open_url("https://github.com/o/r/releases/download/t/f", 16)
                self.assertEqual(str(ctx.exception), reason)
        for final in ("https://github.com/o/r/releases/download/t/f",
                      "https://release-assets.githubusercontent.com/github-production-release-asset/1/2"):
            with self.subTest(final=final):
                opener = mock.Mock()
                opener.open.return_value = Response(final)
                with mock.patch.object(packet.urllib.request, "build_opener",
                                       return_value=opener):
                    self.assertEqual(
                        packet.default_open_url(
                            "https://github.com/o/r/releases/download/t/f", 16), b"")

    def test_cli_refuses_existing_destination_with_exit_2(self):
        with tempfile.TemporaryDirectory() as raw:
            ws = _workspace(Path(raw))
            (ws / packet.PACKET_DIRNAME).mkdir()
            code = packet.main([
                "fetch", "--repository", REPOSITORY, "--tag", TAG,
                "--manifest-sha256", "0" * 64, "--workspace-root", str(ws),
                "--dest", packet.PACKET_DIRNAME,
            ])
            self.assertEqual(code, 2)


class PrepareRecord(unittest.TestCase):
    ENV = {"GITHUB_SHA": SHA_A, "GITHUB_WORKFLOW_SHA": SHA_A,
           "ImageOS": "ubuntu24", "ImageVersion": "20260901.1.0"}

    def test_record_binds_prepare_bytes_to_revision_and_image(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            prepare = base / "prepare.v1.json"
            prepare.write_bytes(b'{"schema": "prepare"}\n')
            out = base / "record" / packet.PREPARE_RECORD_FILENAME
            doc = packet.record_prepare(prepare, out, environ=dict(self.ENV))
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")), doc)
            self.assertEqual(doc["schema"], packet.PREPARE_RECORD_SCHEMA)
            self.assertEqual(doc["prepare_sha256"], _sha256(prepare.read_bytes()))
            self.assertEqual(doc["prepare_bytes"], len(prepare.read_bytes()))
            self.assertEqual(doc["github_sha"], SHA_A)
            self.assertEqual(doc["github_workflow_sha"], SHA_A)
            self.assertEqual(doc["image_os"], "ubuntu24")
            self.assertEqual(doc["image_version"], "20260901.1.0")
            self.assertTrue(doc["non_claims"])

    def test_record_refuses_absent_or_malformed_identity_and_existing_output(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            prepare = base / "prepare.v1.json"
            prepare.write_bytes(b"{}\n")
            for key, value, reason in (
                ("GITHUB_SHA", None, "record_env_absent"),
                ("GITHUB_WORKFLOW_SHA", None, "record_env_absent"),
                ("ImageOS", None, "record_env_absent"),
                ("ImageVersion", "", "record_env_absent"),
                ("GITHUB_SHA", "short", "record_github_sha"),
                ("GITHUB_WORKFLOW_SHA", "Z" * 40, "record_github_workflow_sha"),
            ):
                with self.subTest(key=key, value=value):
                    env = dict(self.ENV)
                    if value is None:
                        del env[key]
                    else:
                        env[key] = value
                    out = base / ("out-%s-%s" % (key, value)) / "r.json"
                    with self.assertRaises(packet.PacketError) as ctx:
                        packet.record_prepare(prepare, out, environ=env)
                    self.assertEqual(str(ctx.exception), reason)
                    self.assertFalse(out.exists())
            existing = base / "existing.json"
            existing.write_bytes(b"x")
            with self.assertRaises(packet.PacketError) as ctx:
                packet.record_prepare(prepare, existing, environ=dict(self.ENV))
            self.assertEqual(str(ctx.exception), "file_exists")
            self.assertEqual(existing.read_bytes(), b"x")


if __name__ == "__main__":
    unittest.main()
