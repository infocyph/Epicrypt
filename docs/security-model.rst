Security Model
==============

Epicrypt uses versioned payloads, embedded algorithm identifiers, and key-id aware rotation helpers to reduce migration risk.

Core principles:

- Secure-by-default APIs.
- Explicit opt-in for unsafe/compatibility modes.
- Strict timestamp validation for signed tokens.
- Separation of crypto capabilities by domain.

Caller responsibilities:

- Protect keys in transit and at rest.
- Rotate keys periodically.
- Re-encrypt legacy data after rotation.
- Enforce TLS and application authorization controls.

