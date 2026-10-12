# Export classification

This repository uses only standard, publicly documented cryptographic algorithms and protocols:
SSH client sessions to target hosts, including host-key scanning, authorized-key parsing and
SHA-256 fingerprinting (Ed25519, RSA and ECDSA key types), via golang.org/x/crypto/ssh;
RS256/ES256 JWT verification of Kubernetes projected ServiceAccount tokens (go-workload-identity)
for service-to-service calls; and TLS to Redis for session state when TLS is enabled on that
connection. None of it is non-standard or proprietary cryptography.

This repository's source code is public, so under the US Export Administration Regulations (15
CFR 742.15(b)) it is not subject to the EAR: no classification, licence or notification applies to
it. Builds and binaries produced from this public source carry the same treatment under 15 CFR
734.3(b)(3) and 734.17.

This file is a factual statement about the cryptography used in Sneakers-PAM, not legal advice.
