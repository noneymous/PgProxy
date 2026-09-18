package pgproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/noneymous/PgProxy/_test"
	scanUtils "github.com/siemens/GoScans/utils"
)

// TestPgReverseProxy_Authentication_ForwardsQueries verifies supported authentication over plaintext and TLS
func TestPgReverseProxy_Authentication_ForwardsQueries(t *testing.T) {

	// Prepare isolated PostgreSQL infrastructure and run each case with its own connection
	port, certificate := test_postgres(t)
	for _, sslMode := range []string{"disable", "require"} {
		for _, user := range []string{"trust_user", "password_user", "md5_user", "scram_user"} {
			t.Run(sslMode+"-"+strings.ReplaceAll(user, "_", "-"), func(t *testing.T) {

				// Prepare unit test data
				proxy := test_proxy(t, port, sslMode, certificate, false)
				conn := test_connect(t, proxy, certificate, user, sslMode == "require")

				// Verify authentication and immediate forwarding of a simple query
				var value int
				if errValue := conn.QueryRow(t.Context(), "SELECT 42", pgx.QueryExecModeSimpleProtocol).Scan(&value); errValue != nil || value != 42 {
					t.Errorf("QueryRow() value = '%d', error = '%v', want = '42, nil'", value, errValue)
				}
			})
		}
	}

	// Verify a PostgreSQL authentication error reaches the client with its original SQLSTATE
	t.Run("wrong-password", func(t *testing.T) {

		// Prepare unit test data with an intentionally incorrect credential
		proxy := test_proxy(t, port, "require", certificate, false)
		config := test_clientConfig(t, proxy, certificate, "scram_user", true)
		config.Password = "incorrect-test-password"
		conn, errConn := pgx.ConnectConfig(t.Context(), config)
		if conn != nil {
			_ = conn.Close(t.Context())
		}

		// Verify the original database error remains available through errors.As
		var errPg *pgconn.PgError
		if !errors.As(errConn, &errPg) || errPg.Code != "28P01" {
			t.Errorf("ConnectConfig() error = '%v', want = 'SQLSTATE 28P01'", errConn)
		}
	})
}

// TestPgReverseProxy_RequiredTls_RejectsPlaintextFallback verifies only optional TLS modes accept SSL rejection
func TestPgReverseProxy_RequiredTls_RejectsPlaintextFallback(t *testing.T) {

	// Prepare an isolated server that explicitly rejects SSL negotiation
	port, certificate := test_postgres(t)
	admin, errAdmin := pgx.Connect(t.Context(), fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=disable", port))
	if errAdmin != nil {
		t.Fatal(errAdmin)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, errQuery := admin.Exec(t.Context(), "ALTER SYSTEM SET ssl='off'"); errQuery != nil {
		t.Fatal(errQuery)
	}
	if _, errQuery := admin.Exec(t.Context(), "SELECT pg_reload_conf()"); errQuery != nil {
		t.Fatal(errQuery)
	}

	// Wait for the real PostgreSQL configuration reload before trying fresh connections
	deadline := time.Now().Add(5 * time.Second)
	for {
		var encrypted string
		if errEncrypted := admin.QueryRow(t.Context(), "SHOW ssl").Scan(&encrypted); errEncrypted != nil {
			t.Fatal(errEncrypted)
		}
		if encrypted == "off" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SHOW ssl = 'on', want = 'off after reload'")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify optional modes retain their fallback while mandatory TLS modes fail closed
	for _, mode := range []string{"allow", "prefer", "require", "verify-ca", "verify-full"} {
		t.Run(mode, func(t *testing.T) {
			proxy := test_proxy(t, port, mode, certificate, false)
			conn, errConn := pgx.ConnectConfig(t.Context(), test_clientConfig(t, proxy, certificate, "scram_user", true))
			if conn != nil {
				_ = conn.Close(t.Context())
			}
			wantError := mode != "allow" && mode != "prefer"
			if (errConn != nil) != wantError {
				t.Errorf("ConnectConfig() error = '%v', want error = '%t'", errConn, wantError)
			}
		})
	}
}

// TestPgReverseProxy_UntrackedCompletion_ClosesWithoutPanic verifies mismatched monitoring state fails cleanly
func TestPgReverseProxy_UntrackedCompletion_ClosesWithoutPanic(t *testing.T) {

	// Prepare real PostgreSQL infrastructure with captured monitoring diagnostics
	port, certificate := test_postgres(t)
	proxy := test_proxy(t, port, "require", certificate, true)
	logger := proxy.logger.(*scanUtils.TestLogger)
	var logs bytes.Buffer
	logger.SetOutput(&logs)

	// Stop forwarding and detach the buffer under the logger lock before inspecting it
	t.Cleanup(func() {
		proxy.Stop()
		logger.SetOutput(io.Discard)
		if strings.Contains(logs.String(), "Panic:") || !strings.Contains(logs.String(), "Statement 1 does not exist in statement sequence.") {
			t.Errorf("Monitoring log = '%s', want = 'missing statement without panic'", logs.String())
		}
	})

	// Connect a client to exercise the real monitoring and response-forwarding path
	conn := test_connect(t, proxy, certificate, "scram_user", true)

	// An escaped quote makes the lightweight splitter track one query while PostgreSQL executes two
	_, errQuery := conn.Exec(t.Context(), `SELECT E'\''; SELECT 2`, pgx.QueryExecModeSimpleProtocol)
	if errQuery == nil {
		t.Error("Exec() error = 'nil', want = 'connection closed for untracked completion'")
	}
}

// TestPgReverseProxy_QueryFlows_PreserveResults verifies extended queries, errors, large rows and COPY
func TestPgReverseProxy_QueryFlows_PreserveResults(t *testing.T) {

	// Prepare isolated PostgreSQL infrastructure with query monitoring enabled as in LSD
	port, certificate := test_postgres(t)
	proxy := test_proxy(t, port, "require", certificate, true)

	// Verify prepared statements, NULL and binary payloads retain their values across repeated executions
	t.Run("prepared-and-large-row", func(t *testing.T) {

		// Prepare unit test data
		conn := test_connect(t, proxy, certificate, "scram_user", true)
		payload := bytes.Repeat([]byte{0, 1, 127, 255}, 2*1024*1024)

		// Verify repeated executions also exercise pgx's prepared-statement cache
		for range 3 {
			var value []byte
			var nullable *string
			errValue := conn.QueryRow(t.Context(), "SELECT $1::bytea, NULL::text", payload).Scan(&value, &nullable)
			if errValue != nil || !bytes.Equal(value, payload) || nullable != nil {
				t.Fatalf("QueryRow() bytes = '%d', NULL = '%v', error = '%v', want = '%d, nil, nil'", len(value), nullable, errValue, len(payload))
			}
		}
	})

	// Verify a SQL error does not prevent subsequent requests on the same connection
	t.Run("error-and-recovery", func(t *testing.T) {

		// Prepare unit test data and provoke a server-side query error
		conn := test_connect(t, proxy, certificate, "scram_user", true)
		_, errQuery := conn.Exec(t.Context(), "SELECT 1/0")

		// Verify both the error classification and the next successful request
		var errPg *pgconn.PgError
		if !errors.As(errQuery, &errPg) || errPg.Code != "22012" {
			t.Errorf("Exec() error = '%v', want = 'SQLSTATE 22012'", errQuery)
		}
		if _, errQuery = conn.Exec(t.Context(), "SELECT 1"); errQuery != nil {
			t.Errorf("Exec() error = '%v', want = 'nil after SQL error'", errQuery)
		}
	})

	// Verify multiple simple-protocol results and an empty query do not remain buffered
	t.Run("multiple-and-empty-queries", func(t *testing.T) {

		// Verify each simple-protocol result and the empty-query acknowledgment are forwarded
		conn := test_connect(t, proxy, certificate, "scram_user", true)
		results, errResults := conn.PgConn().Exec(t.Context(), "SELECT 1; SELECT 2").ReadAll()
		if errResults != nil || len(results) != 2 {
			t.Errorf("Exec() results = '%d', error = '%v', want = '2, nil'", len(results), errResults)
		}
		if _, errQuery := conn.Exec(t.Context(), ""); errQuery != nil {
			t.Errorf("Exec() error = '%v', want = 'nil for empty query'", errQuery)
		}
	})

	// Verify COPY streams are flushed in both directions
	t.Run("copy-in-and-out", func(t *testing.T) {

		// Prepare unit test data in a connection-local temporary table
		conn := test_connect(t, proxy, certificate, "scram_user", true)
		if _, errQuery := conn.Exec(t.Context(), "CREATE TEMP TABLE proxy_copy (value text)"); errQuery != nil {
			t.Fatal(errQuery)
		}
		input := strings.Repeat("test-value\n", 10000)
		if _, errCopy := conn.PgConn().CopyFrom(t.Context(), strings.NewReader(input), "COPY proxy_copy FROM STDIN"); errCopy != nil {
			t.Fatal(errCopy)
		}
		var output bytes.Buffer
		_, errCopy := conn.PgConn().CopyTo(t.Context(), &output, "COPY proxy_copy TO STDOUT")
		if errCopy != nil || output.String() != input {
			t.Errorf("CopyTo() bytes = '%d', error = '%v', want = '%d, nil'", output.Len(), errCopy, len(input))
		}
	})

	// Verify independent simultaneous connections do not mix messages or monitoring state
	t.Run("parallel-clients", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			conn := test_connect(t, proxy, certificate, "scram_user", true)
			wg.Go(func() {
				for range 10 {
					if _, errQuery := conn.Exec(t.Context(), "SELECT 1"); errQuery != nil {
						t.Errorf("Exec() error = '%v', want = 'nil'", errQuery)
						return
					}
				}
			})
		}
		wg.Wait()
	})
}

// TestPgReverseProxy_CancelRequest_ConnectionRemainsUsable verifies cancellation keys reach PostgreSQL intact
func TestPgReverseProxy_CancelRequest_ConnectionRemainsUsable(t *testing.T) {

	// Prepare unit test data
	port, certificate := test_postgres(t)
	proxy := test_proxy(t, port, "require", certificate, true)
	conn := test_connect(t, proxy, certificate, "scram_user", true)
	admin, errAdmin := pgx.Connect(t.Context(), fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=disable", port))
	if errAdmin != nil {
		t.Fatal(errAdmin)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	// Start a real long-running query and wait until PostgreSQL reports it as active
	done := make(chan error, 1)
	go func() {
		_, errQuery := conn.Exec(t.Context(), "SELECT pg_sleep(15)")
		done <- errQuery
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var active bool
		errActive := admin.QueryRow(t.Context(), "SELECT state = 'active' AND query = 'SELECT pg_sleep(15)' FROM pg_stat_activity WHERE pid = $1", conn.PgConn().PID()).Scan(&active)
		if errActive != nil {
			t.Fatal(errActive)
		}
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("QueryRow() active = 'false', want = 'true before cancellation'")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify out-of-band cancellation is delivered and the connection remains reusable
	if errCancel := conn.PgConn().CancelRequest(t.Context()); errCancel != nil {
		t.Fatal(errCancel)
	}
	select {
	case errQuery := <-done:
		var errPg *pgconn.PgError
		if !errors.As(errQuery, &errPg) || errPg.Code != "57014" {
			t.Errorf("Exec() error = '%v', want = 'SQLSTATE 57014'", errQuery)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CancelRequest() query = 'still running', want = 'cancelled'")
	}
	if _, errQuery := conn.Exec(t.Context(), "SELECT 1"); errQuery != nil {
		t.Errorf("Exec() error = '%v', want = 'nil after cancellation'", errQuery)
	}
}

// TestPgReverseProxy_Shutdown_UnblocksActiveAndIdleClients verifies shutdown releases both forwarding directions
func TestPgReverseProxy_Shutdown_UnblocksActiveAndIdleClients(t *testing.T) {

	// Prepare unit test data with one idle connection and one active request
	port, certificate := test_postgres(t)
	proxy := test_proxy(t, port, "require", certificate, true)
	_ = test_connect(t, proxy, certificate, "scram_user", true)
	conn := test_connect(t, proxy, certificate, "scram_user", true)
	done := make(chan error, 1)
	go func() {
		_, errQuery := conn.Exec(t.Context(), "SELECT pg_sleep(15)")
		done <- errQuery
	}()

	// Verify shutdown interrupts transport and does not leave a client waiting for buffered data
	stopped := make(chan struct{})
	go func() { proxy.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() state = 'blocked', want = 'stopped'")
	}
	select {
	case errQuery := <-done:
		if errQuery == nil {
			t.Error("Exec() error = 'nil', want = 'connection closed during shutdown'")
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() state = 'blocked', want = 'connection closed'")
	}
}

// test_postgres starts an isolated real PostgreSQL cluster and removes it after the test
func test_postgres(t *testing.T) (int, tls.Certificate) {

	// Retrieve test settings
	t.Helper()
	settings := _test.GetSettings()
	if settings.PostgresBinDir == "" {
		t.Skip("Integration test skipped: PostgresBinDir not configured in _test/settings.go")
		return 0, tls.Certificate{}
	}

	// Prepare cleanup for all generated files inside the repository's ignored test artifacts directory
	_, source, _, _ := runtime.Caller(0)
	artifacts := filepath.Join(filepath.Dir(source), "..", "_test", "artifacts")
	if errDir := os.MkdirAll(artifacts, 0700); errDir != nil {
		t.Fatal(errDir)
	}
	dir, errDir := os.MkdirTemp(artifacts, "postgres-")
	if errDir != nil {
		t.Fatal(errDir)
	}
	t.Cleanup(func() {
		if errRemove := os.RemoveAll(dir); errRemove != nil {
			t.Error(errRemove)
		}
	})

	// Initialize a fresh cluster with a test-only administrator and select a free loopback port
	test_pgCommand(t, settings.PostgresBinDir, "initdb", "-D", dir, "-U", "postgres", "--auth=trust", "--no-locale", "--encoding=UTF8")
	listener, errListener := net.Listen("tcp", "127.0.0.1:0")
	if errListener != nil {
		t.Fatal(errListener)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	// Generate a short-lived test certificate shared by the isolated server and proxy
	key, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, errDer := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if errDer != nil {
		t.Fatal(errDer)
	}
	keyDer, errKeyDer := x509.MarshalECPrivateKey(key)
	if errKeyDer != nil {
		t.Fatal(errKeyDer)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
	certificate, errCertificate := tls.X509KeyPair(certPem, keyPem)
	if errCertificate != nil {
		t.Fatal(errCertificate)
	}
	certificate.Leaf, _ = x509.ParseCertificate(der)

	// Configure only the disposable cluster; no existing database or authentication settings are changed
	files := map[string][]byte{
		"server.crt":           certPem,
		"server.key":           keyPem,
		"postgresql.auto.conf": []byte("ssl=on\nssl_cert_file='server.crt'\nssl_key_file='server.key'\nunix_socket_directories=''\n"),
		"pg_hba.conf":          []byte("host all postgres 127.0.0.1/32 trust\nhost all trust_user 127.0.0.1/32 trust\nhost all password_user 127.0.0.1/32 password\nhost all md5_user 127.0.0.1/32 md5\nhost all scram_user 127.0.0.1/32 scram-sha-256\n"),
	}
	for name, data := range files {
		if errWrite := os.WriteFile(filepath.Join(dir, name), data, 0600); errWrite != nil {
			t.Fatal(errWrite)
		}
	}
	test_pgCommand(t, settings.PostgresBinDir, "pg_ctl", "-D", dir, "-l", filepath.Join(dir, "server.log"), "-o", fmt.Sprintf("-h 127.0.0.1 -p %d", port), "-w", "start")
	t.Cleanup(func() {
		test_pgCommand(t, settings.PostgresBinDir, "pg_ctl", "-D", dir, "-m", "immediate", "-w", "stop")
	})

	// Create dummy credentials for all authentication methods without affecting any persistent users
	admin, errAdmin := pgx.Connect(t.Context(), fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=disable", port))
	if errAdmin != nil {
		t.Fatal(errAdmin)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	_, errUsers := admin.Exec(t.Context(), "CREATE ROLE trust_user LOGIN; SET password_encryption='md5'; CREATE ROLE md5_user LOGIN PASSWORD 'test-password'; SET password_encryption='scram-sha-256'; CREATE ROLE password_user LOGIN PASSWORD 'test-password'; CREATE ROLE scram_user LOGIN PASSWORD 'test-password';")
	if errUsers != nil {
		t.Fatal(errUsers)
	}

	// Return the isolated endpoint and its test certificate
	return port, certificate
}

// test_pgCommand runs a PostgreSQL administration tool with bounded execution time
func test_pgCommand(t *testing.T, binDir string, name string, args ...string) {

	// Capture tool output in a file so a background PostgreSQL process cannot keep a Go output pipe open
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	output, errOutput := os.CreateTemp(filepath.Join(filepath.Dir(source), "..", "_test", "artifacts"), "tool-*.log")
	if errOutput != nil {
		t.Fatal(errOutput)
	}
	defer func() { _ = output.Close() }()
	t.Cleanup(func() {
		if errRemove := os.Remove(output.Name()); errRemove != nil {
			t.Error(errRemove)
		}
	})

	// Run the real tool with a bounded lifetime and report diagnostic output on failure
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(binDir, name), args...)
	command.Stdout = output
	command.Stderr = output
	if errRun := command.Run(); errRun != nil {
		data, _ := os.ReadFile(output.Name())
		if name == "pg_ctl" && len(args) > 1 {
			serverLog, _ := os.ReadFile(filepath.Join(args[1], "server.log"))
			data = append(data, serverLog...)
		}
		t.Fatalf("%s() error = '%v', want = 'nil': %s", name, errRun, data)
	}
}

// test_proxy starts a real proxy and verifies it drains its connection goroutines on shutdown
func test_proxy(t *testing.T, port int, sslMode string, certificate tls.Certificate, monitoring bool) *PgReverseProxy {

	// Prepare unit test data
	t.Helper()
	logger := scanUtils.NewTestLogger()
	proxy, errProxy := Init(logger, 0, &tls.Config{MinVersion: tls.VersionTLS12}, false, true)
	if errProxy != nil {
		t.Fatal(errProxy)
	}
	errSni := proxy.RegisterSni(Sni{
		Database:        Database{Host: "127.0.0.1", Port: uint16(port), SslMode: sslMode},
		Certificate:     certificate,
		CertificateX509: *certificate.Leaf,
	})
	if errSni != nil {
		t.Fatal(errSni)
	}
	if monitoring {
		proxy.RegisterMonitoring(func(scanUtils.Logger, string, string, []string, string, int, time.Time, time.Time, time.Time, string) error {
			return nil
		})
	}

	// Prepare cleanup and verify both the listener and active handlers terminate promptly
	done := make(chan struct{})
	go func() { proxy.Serve(); close(done) }()
	t.Cleanup(func() {
		stopped := make(chan struct{})
		go func() { proxy.Stop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("Stop() state = 'blocked', want = 'stopped'")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Serve() state = 'blocked', want = 'stopped'")
		}
	})

	// Return the running proxy
	return proxy
}

// test_clientConfig configures a pgx client without reading credentials from the environment
func test_clientConfig(t *testing.T, proxy *PgReverseProxy, certificate tls.Certificate, user string, encrypted bool) *pgx.ConnConfig {

	// Prepare unit test data
	t.Helper()
	config, errConfig := pgx.ParseConfig(fmt.Sprintf("host=127.0.0.1 port=%d dbname=postgres user=%s password=test-password sslmode=disable connect_timeout=5", proxy.listener.Addr().(*net.TCPAddr).Port, user))
	if errConfig != nil {
		t.Fatal(errConfig)
	}
	if encrypted {
		roots := x509.NewCertPool()
		roots.AddCert(certificate.Leaf)
		config.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	}

	// Return the explicitly configured client
	return config
}

// test_connect opens a real PostgreSQL client connection through the proxy and registers cleanup
func test_connect(t *testing.T, proxy *PgReverseProxy, certificate tls.Certificate, user string, encrypted bool) *pgx.Conn {

	// Prepare unit test data
	t.Helper()
	conn, errConn := pgx.ConnectConfig(t.Context(), test_clientConfig(t, proxy, certificate, user, encrypted))
	if errConn != nil {
		t.Fatal(errConn)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	// Return the authenticated client
	return conn
}
