# One signed OKX DEMO control — local unbound candidate

This candidate permits one separately signed `operation=control` only. It loads
the accepted encrypted state, reconciles market/account/fill/bill/valuation
evidence, persists original response bytes, closes the gate and writer, and
decrypts/rechecks the result through a fresh client. Strategy passes and
exchange writes are zero. The first strategy close remains NULL.

The manual hosted workflow has only contents:write/actions:read permissions,
one GitHub-hosted VM, no schedule and no personal access token. The selector and
workflow are not authority. A separate Ed25519 consent must bind the exact future
code/tree/workflow/manifest/capsule, repository/store/root/current head, fresh
control close, actor, run, first attempt, job, runner and finite time window.
Unknown future bindings remain NULL and block. Existing bootstrap consent is
consumed. This release removes bootstrap-consent.json from the current tree;
historical commits and all past grants remain intact.

Successful control publishes exactly three checkpoints: acquisition with durable
grant consumption, market evidence, and final reconciliation with writer NULL.
Each uses three object creates and one non-force update of the existing state
branch. No root creation, foreign ref, force update, retry or writer takeover is
permitted. At most three publications/twelve Git writes including a failure path.
Every publication requires exact parent, immutable object verification and ref
readback. A later missing local receipt never authorizes another control.

OKX is independently GET-only at eea.okx.com with x-simulated-trading:1.
The existing fixed market collectors and original-byte archive remain in use.
No key, account DB, plaintext runtime or private exception belongs in this public
tree. The runtime capsule must be personally encrypted later using the existing
key, then independently reviewed; this source preparation contains no capsule.

Unchanged hard limits: Git total400 calls/240s/32MiB including initial public
fetch and wheel downloads; public fetch additionally64 calls/60s; collector1200
calls/240s/24MiB. Personal public reads retain one durably debited40-call allowance
without refill. Every response must independently cover the remaining local
allowance; regional header variation never creates new allowance. DB, envelope,
compression, archive capacities, original fixed context and freshness limits are
unchanged. Synthetic timings do not prove real operator/provider completion.

No publication, provider call, real control or trading approval has occurred.
Future publication and exactly one run need independent review and specific
user approval. Secret name/scope metadata and actual timing feasibility remain
open; no secret value or private signing key is supplied to this candidate.
