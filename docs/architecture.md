# Architecture

## Capability-First Model

Epicrypt is organized by **responsibility**, not by backend engine.

Top-level capability domains:

- `Certificate`
- `Token`
- `Crypto`
- `DataProtection`
- `Password`
- `Integrity`
- `Generate`
- `Security`
- `Exception`
- `Internal`

## Core Rule

- Top-level domain answers: **what is this for?**
- Backend namespace answers: **how is this implemented?**

Example:

- `Certificate` is the capability
- `Certificate\\OpenSSL` and `Certificate\\Sodium` are backend implementations

## Named Backend Selection

When multiple backends satisfy the same responsibility, Epicrypt exposes named constructors:

```php
use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
use Infocyph\Epicrypt\Certificate\KeyExchange;

$keyExchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
// or:
$keyExchange = KeyExchange::forBackend(KeyExchangeBackend::OPENSSL);
```

## Contracts and Ownership

Contracts live with the capability that owns the behavior.

Examples:

- `Crypto\\Contract\\*`
- `Token\\Contract\\*`
- `Certificate\\Contract\\*`

## Public vs Internal

- Capability entry/service classes are public API surface.
- `Support` and `Internal` classes are implementation details unless explicitly documented as public.
- `Internal\\SignedPayloadCodec` is a shared internal primitive used across domains.

## Security Design Principles

Epicrypt follows:

- safe defaults
- explicit inputs and outputs
- deterministic validation
- fail-closed behavior
- versioned payload framing for sensitive formats
- constant-time comparison for security checks where applicable
