"""Closed identities for hosted measurement rails. No operator-selectable registry."""

from __future__ import annotations

from dataclasses import dataclass

from sealed_measurement_contract import (
    AEE_CHECKER_SEALED_CONTRACT,
    OWNED_CONTAINED_V1_CONTRACT,
    SealedMeasurementContract,
)


@dataclass(frozen=True, slots=True)
class HostedRailContract:
    name: str
    measurement: SealedMeasurementContract
    execution_profile: str
    prepare_filename: str
    packet_manifest_schema: str
    packet_manifest_filename: str
    authorize_filename: str
    bindings_filename: str
    packet_dirname: str
    pins_source: tuple[str, ...]
    prepare_record_schema: str
    prepare_record_filename: str
    workflow_prepare: str
    workflow_publication: str
    prepare_concurrency: str
    publication_concurrency: str
    packet_release_prefix: str
    artifact_prefix: str

    def __post_init__(self) -> None:
        strings = (
            self.name, self.execution_profile, self.prepare_filename,
            self.packet_manifest_schema, self.packet_manifest_filename,
            self.authorize_filename, self.bindings_filename, self.packet_dirname,
            self.prepare_record_schema, self.prepare_record_filename,
            self.workflow_prepare, self.workflow_publication,
            self.prepare_concurrency, self.publication_concurrency,
            self.packet_release_prefix, self.artifact_prefix,
        )
        if any(type(value) is not str or not value or "/" in value or "\\" in value
               for value in strings):
            raise ValueError("hosted rail string")
        if type(self.measurement) is not SealedMeasurementContract:
            raise ValueError("hosted rail measurement")
        if type(self.pins_source) is not tuple or not self.pins_source:
            raise ValueError("hosted rail pins source")
        if any(type(part) is not str or not part or "/" in part or "\\" in part
               or part in (".", "..") for part in self.pins_source):
            raise ValueError("hosted rail pins source")

    @property
    def packet_filenames(self) -> tuple[str, ...]:
        return self.authorize_filename, self.bindings_filename, self.prepare_filename

    @property
    def packet_entries(self) -> tuple[str, ...]:
        return tuple(sorted(self.packet_filenames + (self.packet_manifest_filename, "pins")))


LEGACY_RAIL = HostedRailContract(
    name="aee-contained-v0",
    measurement=AEE_CHECKER_SEALED_CONTRACT,
    execution_profile="contained-oci-v0",
    prepare_filename="prepare.v1.json",
    packet_manifest_schema="corpus-adequacy.hosted-packet-manifest.v0",
    packet_manifest_filename="hosted-packet-manifest.v0.json",
    authorize_filename="authorize.v0.json",
    bindings_filename="hosted-dispatch-bindings.v0.json",
    packet_dirname="hosted-packet",
    pins_source=("measurements", "aee-checker-25b9dfa"),
    prepare_record_schema="corpus-adequacy.hosted-prepare-record.v0",
    prepare_record_filename="hosted-prepare-record.v0.json",
    workflow_prepare="contained-hosted-prepare",
    workflow_publication="contained-hosted-publication",
    prepare_concurrency="contained-hosted-prepare",
    publication_concurrency="contained-hosted-publication",
    packet_release_prefix="hosted-packet-r",
    artifact_prefix="hosted",
)

OWNED_V1_RAIL = HostedRailContract(
    name="owned-contained-v1",
    measurement=OWNED_CONTAINED_V1_CONTRACT,
    execution_profile="contained-oci-v1",
    prepare_filename="prepare.v2.json",
    packet_manifest_schema="corpus-adequacy.owned-contained-v1.hosted-packet-manifest.v1",
    packet_manifest_filename="owned-contained-v1-packet-manifest.v1.json",
    authorize_filename="authorize.v0.json",
    bindings_filename="owned-contained-v1-dispatch-bindings.v1.json",
    packet_dirname="owned-contained-v1-hosted-packet",
    pins_source=("measurements", "owned-contained-v1"),
    prepare_record_schema="corpus-adequacy.owned-contained-v1.hosted-prepare-record.v1",
    prepare_record_filename="owned-contained-v1-prepare-record.v1.json",
    workflow_prepare="owned-contained-v1-prepare",
    workflow_publication="owned-contained-v1-publication",
    prepare_concurrency="owned-contained-v1-prepare",
    publication_concurrency="owned-contained-v1-publication",
    packet_release_prefix="owned-contained-v1-packet-r",
    artifact_prefix="owned-contained-v1",
)


def require_rail(rail) -> HostedRailContract:
    if rail is LEGACY_RAIL or rail is OWNED_V1_RAIL:
        return rail
    raise ValueError("closed hosted rail")
