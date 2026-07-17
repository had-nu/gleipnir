# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| main    | ✅ Active development |
| < main  | ❌ Not supported     |

## Reporting a Vulnerability

Gleipnir is a cryptographic chain-of-custody protocol. Security is critical.

To report a vulnerability privately:

1. **Do not** open a public GitHub issue.
2. Email **andre_ataide@proton.me** with:
   - Subject: `Gleipnir Security Vulnerability`
   - Description of the issue
   - Steps to reproduce
   - Affected versions/components
   - Any proposed fix (optional)

You will receive an acknowledgment within **48 hours**, and a detailed response within **5 business days** including next steps and estimated fix timeline.

## Responsible Disclosure

We ask that you allow us reasonable time to address the issue before any public disclosure. We strive to:

- Acknowledge receipt within 48 hours
- Provide an initial assessment within 5 business days
- Release a fix as soon as practical, depending on severity

## Scope

The following areas are in scope:

- Post-quantum cryptography integration (Dilithium3, Kyber1024, ECVRF)
- Consensus engine and quorum logic
- Sparse Merkle Tree implementation
- State transition and Laplacian diffusion supervision
- gRPC API and transport layer (libp2p, TLS)
- Storage and persistence layer (BoltDB)

## Out of Scope

- Third-party dependencies (report to their respective maintainers)
- Theoretical attacks not demonstrated against the specific implementation
- Social engineering attacks against contributors
