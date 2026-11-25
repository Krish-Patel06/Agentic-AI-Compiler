# Non-AI Authoritative Policy Engine

Immutable rules, quotas, and pass allowlists loaded from cryptographically signed configuration.

## Files
- `policy_config.json`: Canonical policy rules (pass allowlist, forbidden list, security caps).
- `policy_config.sig`: Detached HMAC-SHA256 signature for tamper verification.
- `policy_loader.py`: Cryptographic verification and loading of authoritative policy.
- `schema_validator.py`: Zero-dependency JSON schema validator enforcing strict types.
- `schemas/`: Strict schemas for `agent_proposal.json`, `test_vectors.json`, and `advisory.json`.
