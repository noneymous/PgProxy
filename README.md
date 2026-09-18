# PgProxy - Postgres Reverse Proxy
PgProxy is a Postgres reverse proxy, accepting database connections from clients (e.g. database browsers or other scripts) with a configured certificate
and redirecting them to the actual Postgres database. Clients see the configured certificate, rather than the actual one from the Postgres database.

PgProxy allows to configure multiple SNIs. Different SNIs can present different SSL certificates to the client. 
Furthermore, each SNI can redirect the client to a different Postgres database.

PgProxy can optionally log user queries and execution times. A custom function can be defined working, processing or storing that data.

PgProxy is especially handy, if you are using Amazon RDS in a way allowing clients/users to directly connect to the database.
Amazon RDS deploys with an SSL certificate issued by Amazon, which cannot be verified by clients/users without further configuration, or which might confuse your users.
There is no simple way to deploy your own SSL certificate on Amazon RDS.
Putting an NLB (network load balancer) with a TLS listener in front does not help, since Postgres starts communication with an unencrypted connection and upgrades to SSL in the process only.
Hence, also an NLB would still deliver the Amazon RDS' certificate.


# Sample use

Please refer to main.go for a fully working sample

```

	// Initialize PgProxy
	pgProxy, errPgProxy := pgproxy.Init(logger, 54321, timeout)
	if errPgProxy != nil {
		logger.Errorf("Could not initialize PgProxy: %s.", errPgProxy)
		return
	}
	
	...
	
	
	// Register monitoring function (optional)
	pgProxy.RegisterMonitoring(func(q string, qStart time.Time, qEnd time.Time, resultRows int, user string) error {

		// Indent lines
		logMsg := "    " + strings.Join(strings.Split(q, "\n"), "\n    ")

		// Log query with stats
		logger.Debugf("Query of user '%s' returned %d row(s) in %s: \n%s", user, resultRows, qEnd.Sub(qStart), logMsg)

		// Return from monitoring function
		return nil
	})
	
	...
	
	
	// Register proxy interfaces and routes
	errAdd := pgProxy.RegisterSni(snis...)
	if errAdd != nil {
		logger.Errorf("Could not add PgProxy SNI: %s.", errAdd)
		return
	}
	
	...
	
	
	// Listen and serve connections
	pgProxy.Serve()

```

## Tests

Run `go test ./...` for unit and protocol regression tests. Integration tests additionally need local PostgreSQL
executables. Configure `PostgresBinDir` in `_test/settings.go`, or provide it with Go's linker flag:

Linux (with a C compiler installed for the race detector):

```sh
GOTOOLCHAIN=go1.26.8 CGO_ENABLED=1 go test -race ./... -ldflags='-X github.com/noneymous/PgProxy/_test.PostgresBinDir=/usr/lib/postgresql/18/bin'
```

Windows PowerShell (without the race detector):

```powershell
$env:GOTOOLCHAIN = 'go1.26.8'
go test ./... -ldflags='-X "github.com/noneymous/PgProxy/_test.PostgresBinDir=C:/Program Files/PostgreSQL/18/bin"'
```

Adjust the PostgreSQL binary path to your installation. On Windows, `-race` additionally requires `CGO_ENABLED=1`
and a Go-compatible C compiler on `PATH`; alternatively, run the Linux command inside WSL. The `_test` directory is
an explicitly imported configuration package, not a test-discovery target of `./...`. Its full import path in `-X`
sets the configuration used by the integration tests in `pgproxy/`.

The integration tests create disposable, loopback-only clusters and dummy users under `_test/artifacts/`. They do not
use existing databases. Generated clusters and certificates are removed after the tests. Use a current patched Go
toolchain for release builds; validation of this migration used Go 1.26.8 and PostgreSQL 18.
