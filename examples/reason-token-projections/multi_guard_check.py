"""Synthetic ordered checks; no digest or cryptographic validation."""
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    vector = json.load(stream)
state = "fail"
unused = "constant"
if not vector["payload_ok"]:
    reason = "payload-digest"
elif not vector["artifact_ok"]:
    reason = "artifact-digest"
else:
    state = "pass"
    reason = "ok"
print(json.dumps({"state": state, "reason": reason}))
