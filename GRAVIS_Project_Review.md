# GRAVIS AI project review

**Review date:** 10 October 2026  
**Scope:** The supplied “Complete R&D & Technical Documentation Blueprint” text. No application source files, slide deck, database, or other project artifacts were present in the workspace, so implementation and visual claims could not be independently verified.

## Executive summary

The brief describes a Digital Risk Protection platform with brand and phishing monitoring, threat scoring, case management, a dashboard, and an ambitious multi-signal registration flow. It reports **75% complete**, with frontend and backend marked complete, while crawlers, scoring, and case management remain partial.

The document is a useful architecture draft, but the claim that the updated work is “perfect” is not supported. The included server code has a critical account-registration/login mismatch and several security, validation, and reporting problems. The stated completion percentages also lack a calculation method. The analytics color legend and registration pipeline are specifications; the actual UI and behavior were not supplied for review.

**Key point retained for this conversation:** GRAVIS’s positioning statement is **“YOUR PRIVACY IS OUR POLICY.”**

## What the project says it contains

- **Product:** GRAVIS AI Risk Protection Platform, targeting digital risk protection, brand protection, anti-phishing, and social/app impersonation detection.
- **User experience:** deep emerald branding, a split green/white login page, privacy banner, multi-signal registration, and a dark analytics view.
- **Backend:** Express, MongoDB/Mongoose, JWT, bcrypt, Socket.IO, user and registration schemas, threat schema, ingestion API, risk score function, and dashboard counts.
- **Risk scoring:** brand similarity, logo similarity, suspicious URL, and account age contribute to a score capped at 100, with LOW/MEDIUM/HIGH/CRITICAL bands.
- **Remaining work listed:** crawler integrations, cloud hosting, and PDF incident exports.
- **Analytics colors:** blue admin, green standard, red unverified/threat, grey multi-device.

## Findings and corrections needed

### Critical: registration cannot sign in

The registration endpoint saves records in `UserRegistration` with `passwordHash`. The login endpoint searches the separate `User` collection and compares against `user.password`. A user created by the supplied registration endpoint therefore cannot log in through the supplied login endpoint.

**Correction:** use one canonical account model for both routes, persist the hash there, and have login look up that same model and compare against its hash. If the two collections are intentionally distinct, define and implement the account-linking flow. Do not store plaintext passwords.

### Critical: credentials are treated as verified without proof

The registration route sets mobile OTP and secondary email verification to `true` unconditionally. It treats client-supplied face, liveness, WebAuthn, and VPN fields as authoritative and may activate an account based only on those values. This does not verify an OTP, email ownership, biometric liveness, or a WebAuthn assertion.

**Correction:** keep the account pending until server-validated OTP/email challenges and a proper WebAuthn registration ceremony succeed. Validate biometric/liveness results through a trusted verifier, not a client-provided score. Make any location policy decision server-side and document user consent.

### Critical: secrets and access controls

The JWT secret has a predictable hard-coded fallback. CORS allows every origin. Threat ingestion is unauthenticated, so arbitrary callers can create threat records and broadcast them to connected clients. The Socket.IO connection is also unauthenticated.

**Correction:** require a strong secret from deployment configuration and fail startup if missing in production; allow only configured origins; authenticate and authorize ingestion and socket connections; rate-limit sensitive endpoints. Separate service-to-service ingestion credentials from user sessions where appropriate.

### High: request validation and failure handling

Routes assume required fields and valid types. Missing `signals` can fail scoring; similarity values, account age, URLs, channels, and evidence are not bounded or validated. Duplicate-key and validation failures return HTTP 500, which incorrectly labels client errors as server failures. The registration route can hash an absent password.

**Correction:** define request schemas and reject malformed inputs with 400/422; validate numeric ranges and enums; handle duplicate records as 409; avoid returning raw internal error messages to clients. Require a sufficiently strong password or replace password auth with the intended credential flow.

### High: location validity check rejects legitimate coordinates

`locationData.latitude && locationData.longitude` treats zero as missing, even though latitude or longitude can validly be 0.

**Correction:** check that each coordinate is a finite number and is within latitude [-90, 90] / longitude [-180, 180], rather than testing truthiness.

### High: scoring scale is unspecified and can be wrong

The weights multiply similarity values by 0.35 and 0.25. If similarities are percentages from 0–100, their maximum contribution is only 60 points; if values are fractions from 0–1, the contribution is negligible. Negative and out-of-range inputs are accepted. The intended scale and weight normalization are not documented.

**Correction:** define the input scale explicitly, normalize each signal, validate bounds, and document the maximum contribution. Add examples of expected inputs and outputs before calling the scoring model production-ready.

### Medium: status and dashboard semantics are misleading

The account status enum includes `PENDING_VERIFICATION`, but the registration code marks accounts `FLAGGED` when checks fail rather than leaving them pending. The “suspiciousAccounts” dashboard count counts every social-media threat, not suspicious accounts. It does not count accounts or deduplicate them.

**Correction:** use pending for incomplete verification and flagged for a completed risk decision. Rename the metric to “socialMediaThreats” or implement a distinct suspicious-account count based on a defined entity and query.

### Medium: analytics legend mixes user roles and event categories

Admin and standard-user entries are roles, while threat and multi-device entries describe alert/session conditions. These can overlap, so one color per profile is ambiguous.

**Correction:** define colors for distinct event classes or separate role and event indicators. Show how a multi-device admin session is represented.

### Medium: privacy and architecture claims exceed the implementation

The brief promises “zero-knowledge biometric hash,” 3D facial capture, geofencing, anti-spoofing, and cryptographic session signing, but the code only stores supplied fields and has no implementation for those controls. Storing face-derived data and precise location creates sensitive-data risks.

**Correction:** label these as planned capabilities until implemented; specify data minimization, consent, encryption, access controls, retention/deletion, and a threat model. Avoid calling a face mesh hash “zero-knowledge” without a defined cryptographic protocol and independent review.

### Medium: completion percentage is not reproducible

The overall 75% figure is not derived from the component percentages. The simple average of the five listed component values is **72%**, but that may not reflect effort or importance. “Completed” also conflicts with several claimed features that have no implementation in the supplied code.

**Correction:** publish the weighting formula and evidence criteria, distinguish implemented/tested/deployed, and recalculate from verifiable work items. Until then, present 75% as an estimate, not a measured completion result.

## Recommended order of work

1. Unify registration and login around one account record; add request validation and safe error handling.
2. Remove trust in client-asserted verification; implement actual email/OTP and WebAuthn verification with pending-state transitions.
3. Lock down JWT configuration, CORS, threat ingestion, and WebSocket access.
4. Specify, normalize, and validate scoring inputs; define dashboard metric semantics.
5. Document privacy controls and revise feature/completion claims to match verified implementation.
6. Then assess the UI, crawler coverage, case management, PDF export, and deployment against the blueprint.

## Overall assessment

**Not perfect yet.** The blueprint is structured and communicates the intended product, but the embedded server code is not internally consistent for account lifecycle, does not perform the verification it claims, and is not ready for production exposure. I could not apply code changes because no editable project source was supplied; the only available artifact was the pasted brief. The findings above identify the corrections to apply once the source project is available.
