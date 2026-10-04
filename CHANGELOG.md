# Changelog

## 4.2.1-gk.9 — 2026-10-04

- Add optional native SOCKS authentication through `--socks-auth-file` in `socks` and `l4-socks`. Linux requires a regular, nonsymlink root:usque file with mode 0640 and bounded JSON containing only username and password, each 1..255 UTF-8 bytes.
- Add `USQUE_SOCKS_AUTH_FILE` to the supervisor. Credentials stay out of child arguments, errors and runtime state. Local health probes require username/password authentication and reject an anonymous fallback while preserving remote DNS and bounded cancellation.
- Preserve the TCP association's local IPv4 address on SOCKS UDP replies, including wildcard listeners serving separate public and private addresses. WARP transport source selection and service privileges are unchanged.
- Keep the existing loopback, unauthenticated profile when no credential file is configured. There is no built-in default username or password.
