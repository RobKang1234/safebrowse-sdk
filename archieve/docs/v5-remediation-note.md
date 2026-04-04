# SafeBrowse V5 Remediation Note

This note is preserved for history. It captures the repo-safe summary of the independent V4 audit feedback that drove the earlier V5 redesign. The current claim-bearing line is V6; the original auditor `.docx` files remain local-only and are not committed to the repository.

## Historical V5 Claim

V5 narrowed the public claim to unauthorized-effects prevention under the `secure_v5` deployment profile. The claim was not "malicious text never reaches the model." The claim was that supported V5 surfaces did not directly mint effectful authority or advance privileged connector or trusted-state flows without a server-issued capability and a broker-issued approval envelope bound to the exact action.

## Main Remediations

- Added a new V5 route family instead of extending the older V4 claim surface.
- Moved V5 authority away from caller-supplied trust metadata and toward server-owned observation storage, capability minting, and approval issuance.
- Limited effectful capability minting to visible HTML link spans, verified tool manifests, and server-owned memory promotion paths.
- Added digest-bound, non-replayable V5 capabilities and broker-signed approval envelopes.
- Bound connector preparation and callback verification to stored capability, workflow, registry, callback, and session state.
- Added `secure_v5` deployment posture with legacy route disablement, verified-registry requirement, parser-isolation requirement, and approval-broker requirement.
- Kept wrapper parity and auditor review as blocking gates across direct, Python, and npm-installed execution paths.

## Historical Evidence

The deterministic V5 secure-claim suite lives in [config/auditor/v5_secure_claim_suite.json](../config/auditor/v5_secure_claim_suite.json). The latest validated run is always refreshed under [demo-output/latest](../demo-output/latest).

Historical local status on March 30, 2026:

- secure-claim suite: `7/7` passing
- wrapper parity: direct, Python, and npm-installed paths aligned
- verdict: `qualified_positive_pending_external_audit`

## Historical Qualification

V5 is still a qualified claim because:

- parser isolation is process-level hardening, not a full OS or container sandbox
- the external auditor has not yet reissued a final opinion on the V5 secure profile
- the claim remains intentionally narrower than "prevent prompt injection"
