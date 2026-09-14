"""Closed source identity for a sealed measurement. Stdlib only.

The contract is code-owned and immutable. It is not a manifest format or an
operator-selectable registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_PIN_NAMES = frozenset({"control.json", "manifest.json", "pins.json", "sites.json"})


def _require_relpath(value: str, where: str) -> None:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("%s must be a safe relative path" % where)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("%s must be a safe relative path" % where)


def _require_tuple(value, where: str) -> None:
    if type(value) is not tuple or not value:
        raise ValueError("%s must be a non-empty tuple" % where)


def _is_hex(value, pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class SealedMeasurementContract:
    """Immutable identity values for one closed measurement implementation."""

    name: str
    pins_relpath: tuple[str, ...]
    instrument_commit: str
    pin_digests: tuple[tuple[str, str], ...]
    adapter_relpath: str
    adapter_sha256: str
    corpus_manifest_sha256: str
    subject_tree_sha256: str
    corpus_tree_sha256: str
    subject_subdir: str | None
    corpus_subdir: str | None
    corpus_id_count: int
    mutation_group: str
    control_id: str
    inert_control_ids: tuple[str, ...]
    site_ids: tuple[str, ...]
    operator: str
    execution_paths: tuple[str, ...]
    container_context_relpath: str
    candidate_build: tuple[str, ...]
    candidate_entrypoint: tuple[str, ...]
    candidate_complete_returncodes: tuple[int, ...]
    vendor_tree_requirement: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("contract name")
        _require_tuple(self.pins_relpath, "pins_relpath")
        for part in self.pins_relpath:
            _require_relpath(part, "pins_relpath")
            if "/" in part:
                raise ValueError("pins_relpath must contain path components")
        _require_relpath(self.adapter_relpath, "adapter_relpath")
        _require_relpath(self.container_context_relpath, "container_context_relpath")
        for where, value in (
            ("subject_subdir", self.subject_subdir),
            ("corpus_subdir", self.corpus_subdir),
        ):
            if value is not None:
                _require_relpath(value, where)
        if not _is_hex(self.instrument_commit, _HEX40):
            raise ValueError("instrument_commit must be lowercase hex")

        _require_tuple(self.pin_digests, "pin_digests")
        names = []
        for row in self.pin_digests:
            if type(row) is not tuple or len(row) != 2:
                raise ValueError("pin_digests row")
            name, digest = row
            _require_relpath(name, "pin name")
            if "/" in name or not _is_hex(digest, _HEX64):
                raise ValueError("pin_digests row")
            names.append(name)
        if len(names) != len(set(names)) or frozenset(names) != _PIN_NAMES:
            raise ValueError("pin_digests must contain the closed pin set")

        for where, digest in (
            ("adapter_sha256", self.adapter_sha256),
            ("corpus_manifest_sha256", self.corpus_manifest_sha256),
            ("subject_tree_sha256", self.subject_tree_sha256),
            ("corpus_tree_sha256", self.corpus_tree_sha256),
        ):
            if not _is_hex(digest, _HEX64):
                raise ValueError("%s must be lowercase hex" % where)
        if type(self.corpus_id_count) is not int or self.corpus_id_count <= 0:
            raise ValueError("corpus_id_count must be positive")

        for where, value in (
            ("mutation_group", self.mutation_group),
            ("control_id", self.control_id),
            ("operator", self.operator),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(where)
        _require_tuple(self.site_ids, "site_ids")
        if any(not isinstance(value, str) or not value for value in self.site_ids):
            raise ValueError("site_ids")
        if type(self.inert_control_ids) is not tuple or any(
                not isinstance(value, str) or not value
                for value in self.inert_control_ids):
            raise ValueError("inert_control_ids")
        if len(self.inert_control_ids) != len(set(self.inert_control_ids)):
            raise ValueError("inert_control_ids must be unique")
        identities = (self.control_id,) + self.inert_control_ids + self.site_ids
        if len(identities) != len(set(identities)):
            raise ValueError("control and site ids must be disjoint")

        _require_tuple(self.execution_paths, "execution_paths")
        if len(self.execution_paths) != len(set(self.execution_paths)):
            raise ValueError("execution_paths must be unique")
        for value in self.execution_paths:
            _require_relpath(value, "execution_paths")
        for where, command in (
            ("candidate_build", self.candidate_build),
            ("candidate_entrypoint", self.candidate_entrypoint),
        ):
            _require_tuple(command, where)
            if any(not isinstance(value, str) or not value for value in command):
                raise ValueError(where)
        _require_tuple(
            self.candidate_complete_returncodes, "candidate_complete_returncodes")
        if (len(self.candidate_complete_returncodes) !=
                len(set(self.candidate_complete_returncodes)) or any(
                    type(value) is not int or value < 0 or value > 255
                    for value in self.candidate_complete_returncodes)):
            raise ValueError("candidate_complete_returncodes")
        if type(self.vendor_tree_requirement) is not str or self.vendor_tree_requirement not in (
                "nonempty", "canonical-empty"):
            raise ValueError("vendor_tree_requirement")

    def pin_digest(self, name: str) -> str:
        for candidate, digest in self.pin_digests:
            if candidate == name:
                return digest
        raise KeyError(name)


AEE_CHECKER_SEALED_CONTRACT = SealedMeasurementContract(
    name="aee-checker-sealed",
    pins_relpath=("measurements", "aee-checker-25b9dfa"),
    instrument_commit="1347651c2087cbd5c2e958a758b380a9a6cfc67d",
    pin_digests=(
        ("control.json", "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71"),
        ("manifest.json", "d21f4831c48a633009cafb0672c2d4e986bffda21a2c82508c1b32486d414eee"),
        ("pins.json", "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4"),
        ("sites.json", "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c"),
    ),
    adapter_relpath="adapters/aee_checker_sealed.py",
    adapter_sha256="130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769",
    corpus_manifest_sha256="aaee0241d5f92a65ecfa603113f5c313b3f0593aa97ce8a54732287f0dc26c67",
    subject_tree_sha256="393d742154918f640593fe9962cf87a273a28c93b24c0569ee4bef3a039fdc3d",
    corpus_tree_sha256="4bd2f2bf1208beb613fef0e6cc4728483cecae1097b74b54baaf54ce22569c42",
    subject_subdir=None,
    corpus_subdir=None,
    corpus_id_count=250,
    mutation_group="sealed",
    control_id="control",
    inert_control_ids=(),
    site_ids=tuple("sealed-%d" % index for index in range(1, 8)),
    operator="whole-condition-to-false",
    execution_paths=(
        "bounded_run.py",
        "corpus_adequacy.py",
        "isolated_tree.py",
        "module_child.py",
        "adapters/aee_checker_sealed.py",
        "measurements/aee-checker-25b9dfa/manifest.json",
        "measurements/aee_checker_sealed_run.py",
        "measurements/aee_checker_sealed_common.py",
        "measurements/contained_oci.py",
        "measurements/effective_envelope.py",
        "measurements/envelope_collection.py",
        "measurements/aee_checker_sealed_oci.py",
        "measurements/aee_checker_sealed_candidate.py",
        "measurements/aee_checker_sealed_materialize.py",
        "measurements/aee_checker_sealed_authorize.py",
        "measurements/aee_checker_sealed_execute.py",
        "measurements/aee_checker_sealed_driver.py",
        "measurements/aee_checker_sealed_runtime.py",
        "measurements/sealed_measurement_contract.py",
        "execution/aee-checker-sealed/Containerfile",
        "execution/aee-checker-sealed/probe.sh",
        "execution/aee-checker-sealed/cargo-config.toml",
    ),
    container_context_relpath="execution/aee-checker-sealed",
    candidate_build=("cargo", "build", "--release", "--locked", "--offline"),
    candidate_entrypoint=(
        "/work/target/release/aee-checker", "/input/vectors", "--json", "/work/report.json",
    ),
    candidate_complete_returncodes=(0, 1),
    vendor_tree_requirement="nonempty",
)


OWNED_CONTAINED_V1_CONTRACT = SealedMeasurementContract(
    name="owned-contained-v1",
    pins_relpath=("measurements", "owned-contained-v1"),
    instrument_commit="0e69b834aa62c7f0fb2bff331884d6ee66a97bfe",
    pin_digests=(
        ("control.json", "b34629777838968cb239e4c9bc533c740409c58e7d245722e8c5408a94ac1057"),
        ("manifest.json", "d73dbef6b535bc61ecb8855a59bed8228c760fc9c978d6e26dc50b3162c8ac26"),
        ("pins.json", "442c9b891362f1bc28350d6050535fbacf6186c30d5995f0ed4f2f38cb0b2ab4"),
        ("sites.json", "3de344ef7db927aae69b41c379379d67512685796589e55141f840f293a830ce"),
    ),
    adapter_relpath="adapters/owned_contained_v1.py",
    adapter_sha256="30de9ed72184ff3d90b20be919312a4f4c92a786c68c33480150b6308ac209d1",
    corpus_manifest_sha256="979b9367f9662d2df45ec1078f0b4b4466e77a0dca163ea19ca2a60c44c267ec",
    subject_tree_sha256="6a6ae2e47737c972f89b7017faa9842b1a8c3ed0b881bc0d6e293dfd0f13b7ca",
    corpus_tree_sha256="83e6b981cf2b55812dd6d47c7dcd45da855d8019206744962e8ec0239888ddd3",
    subject_subdir="fixtures/contained-v1-owned/candidate",
    corpus_subdir="fixtures/contained-v1-owned/corpus",
    corpus_id_count=4,
    mutation_group="owned",
    control_id="control-positive",
    inert_control_ids=("control-inert",),
    site_ids=("negative-guard", "upper-guard"),
    operator="whole-condition-to-false",
    execution_paths=tuple(
        "adapters/owned_contained_v1.py" if path == "adapters/aee_checker_sealed.py"
        else "measurements/owned-contained-v1/manifest.json"
        if path == "measurements/aee-checker-25b9dfa/manifest.json"
        else path
        for path in AEE_CHECKER_SEALED_CONTRACT.execution_paths
    ),
    container_context_relpath="execution/aee-checker-sealed",
    candidate_build=("cargo", "build", "--release", "--locked", "--offline"),
    candidate_entrypoint=(
        "/work/target/release/corpus-adequacy-owned-fixture",
        "/input/vectors", "--json", "/work/report.json",
    ),
    candidate_complete_returncodes=(0,),
    vendor_tree_requirement="canonical-empty",
)
