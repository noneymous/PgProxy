# Changelog

- 2026-11-24 | fix | Query monitoring | Supply surrounding formatter context so statements such as EXPLAIN UPDATE retain their keyword boundaries in query logs.
- 2026-11-24 | fix | Connection lifecycle | Treat database writes interrupted by a locally closed connection as cleanup diagnostics instead of errors, avoiding misleading failure reports during shutdown.
- 2026-10-23 | fix | Query monitoring | Correctly split multi-statement requests containing quoted comment markers, continued escaped strings, dollar quoting, nested comments, SQL routine bodies and rule action lists, preventing valid queries and exports from being disconnected. Honor acknowledged server string-mode changes and ignore comment-only fragments that produce no statement completion.
- 2026-09-14 | security | PostgreSQL protocol | Replaced the archived pgproto3/v2 and pgconn packages with pgx/v5, preventing malformed row-length panics while preserving immediate forwarding, authentication, TLS and cancellation. Cancellation keys now retain their full length; `PgConn.Sid` is a byte slice and `ErrInternal` uses the pgx/v5 `PgError` type.
- 2026-09-14 | reliability | Connection lifecycle | Synchronized shared forwarding state and wait for both receiver goroutines to finish during shutdown, preventing data races and premature connection cleanup.
- 2026-09-14 | security | Database TLS | Reject plaintext fallback for verify-ca and verify-full when the database refuses SSL, matching the encryption guarantee of those modes.
- 2026-09-14 | reliability | Query monitoring | Reject unmatched completion responses without panicking and retain the original query with the usual whitespace cleanup when tokenization fails, avoiding parser panics during monitoring.
