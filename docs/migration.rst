Migration
=========

Recommended migration flow:

1. Start writing with current compact payload formats and active key ids.
2. Keep old keys in key rings for read-path compatibility.
3. Re-encrypt legacy strings/files/envelopes to active key ids.
4. Remove retired keys after successful migration and verification.

JWT migration notes:

- Enforce strict validation incrementally with result APIs.
- Require ``kid`` when using key-set verification mode.

