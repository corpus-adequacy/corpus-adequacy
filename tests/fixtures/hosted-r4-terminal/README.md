# Retained external candidate result (r4)

`candidate-result.json` is the `candidate-result` artifact of hosted run 35194072925 attempt 1
(`contained-hosted-publication`, runner `1345bac5d5853824a6de00dda9a7b03efd906236`), byte for byte
as extracted from the `candidate-result.zip` asset of the immutable release
`aee-contained-v0-terminal-35194072925-1`. The tool wrote it; it holds no third-party content.

SHA-256 `0ac4b193e23cfff205f68bcb51c065d5a4223c05089c5aa222c3cee6a77acb38`.

It is the historical `corpus-adequacy.hosted-publication.v0` shape, which carries no
`report_sha256`. The gate no longer writes that shape (#184); the loader keeps reading it so the
retained r1 and r4 bytes stay checkable.

`effective-envelope/` is the extracted `effective-envelope.zip` asset of the same release: the
v0 collection index (SHA-256 `b899299ac8f8c85f3acda6f739bfe30dbe11aa62fa1f3f5f12f46d3c9764cb61`)
and its nine byte-identical members. It is the historical v0 index shape, which carries no step
attribution; the loader keeps reading it (#185).

`setup-status.json` (SHA-256 `1c2cac5834145edf22997a29ab00aa2beea2ba33e1e388b46127a5041025d32e`)
and `rerun-evidence.jsonl` (SHA-256
`90f3f0609a5b01625ef624870941b8ea0b2db0e271ab392f4d7782b8854197db`) are the other two artifacts
of the same attempt, extracted from the same release. With the candidate result and the
collection they form the complete published set, so `readback` of these bytes at the current
revision is pinned as a regression test (#188).
