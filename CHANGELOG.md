# Changelog

- 2026-09-14 | security | PostgreSQL protocol | Replaced the archived pgproto3/v2 and pgconn packages with pgx/v5, preventing malformed row-length panics while preserving immediate forwarding, authentication, TLS and cancellation. Cancellation keys now retain their full length; `PgConn.Sid` is a byte slice and `ErrInternal` uses the pgx/v5 `PgError` type.
- 2026-09-14 | reliability | Connection lifecycle | Synchronized shared forwarding state and wait for both receiver goroutines to finish during shutdown, preventing data races and premature connection cleanup.
- 2026-09-14 | security | Database TLS | Reject plaintext fallback for verify-ca and verify-full when the database refuses SSL, matching the encryption guarantee of those modes.
- 2026-09-14 | reliability | Query monitoring | Reject unmatched completion responses without panicking and retain the original query with the usual whitespace cleanup when tokenization fails, avoiding parser panics during monitoring.
