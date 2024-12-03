package pgproxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/lithammer/shortuuid/v4"
	"github.com/noneymous/go-sqlfmt/sqlfmt"
	"github.com/noneymous/go-sqlfmt/sqlfmt/formatters"
	"github.com/noneymous/go-sqlfmt/sqlfmt/lexer"
	"github.com/noneymous/go-sqlfmt/sqlfmt/parser"
	cmap "github.com/orcaman/concurrent-map/v2"
	scanUtils "github.com/siemens/GoScans/utils"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const intervalConnectionsLog = time.Second * 60

// ErrInternal defines an error message to be returned to the client if there was some internal error
// Other errors, raised by the database, should be directly returned to the client.
var ErrInternal = &pgconn.PgError{
	Severity: "FATAL",
	Message:  "database currently not available",
}

// ErrCertificate is returned if no suitable certificate could be found
type ErrCertificate struct {
	Message string
}

func (e *ErrCertificate) Error() string {
	return e.Message
}

type PgConn struct {
	Uuid             string // random string identifying log messages of this connection stream
	Pid              uint32
	Sid              uint32
	Db               string
	User             string
	Application      string
	Timestamp        time.Time
	TimestampLast    time.Time
	ConnectionDb     net.Conn
	ConnectionClient net.Conn
	QueryInProgress  bool
}

// PgReverseProxy defines a Postgres reverse proxy listening on a certain port, accepting incoming client
// connections and redirecting them to configured database servers, based on SNIs indicated by the client.
type PgReverseProxy struct {
	logger             scanUtils.Logger // PgProxy internal logger. Can be any fulfilling the specified logger interface
	listener           net.Listener     // PgProxy net listener listening for incoming client connections to be proxied
	listenerPort       uint             // PgProxy port to listen on
	listenerTlsConf    *tls.Config      // TLS configuration to use to service clients
	listenerForceTls   bool             // PgProxy flag whether to force SSL or allow plaintext connections
	listenerDefaultSni bool             // PgProxy flag whether to enable first listener config as default or to demand suitable SNI for incoming SSL connections
	listenerConfigs    map[string]Sni   // List of SNI certificates and database configurations to redirect clients

	connectionMap cmap.ConcurrentMap[string, *PgConn] // Map to lookup network connections by backend key data
	connectionCnt uint                                // Counter for currently active proxy connections

	wg            sync.WaitGroup     // Wait group for all goroutines across all client connections
	ctx           context.Context    // Context within the PgProxy is running, can be cancelled to shut down
	ctxCancelFunc context.CancelFunc // Cancel function for context

	connectionsLogTicker *time.Ticker // Ticker regularly logging currently active connections

	fnMonitoring func(
		loggerClient scanUtils.Logger,
		dbName string,
		dbUser string,
		dbTables []string,
		query string,
		queryResults int,
		queryStart time.Time,
		queryEndExec time.Time,
		queryEndTotal time.Time,
		clientName string,
	) error
}

// Init initializes the Postgres reverse proxy
func Init(
	logger scanUtils.Logger,
	listenerPort uint,
	listenerTlsConf *tls.Config,
	listenerForceTls bool, // Whether to reject plain text connections
	listenerDefaultSni bool, // Whether to reject SSL connections without SNI. Without SNI the first SNI configuration would be applied as the default.
) (*PgReverseProxy, error) {

	// Open listener
	listener, errListener := net.Listen("tcp", fmt.Sprintf(":%d", listenerPort))
	if errListener != nil {
		return nil, errListener
	}

	// Prepare cancel context
	ctx, ctxCancel := context.WithCancel(context.Background())

	// Prepare PgProxy
	pgProxy := PgReverseProxy{
		logger:               logger,
		listener:             listener,
		listenerPort:         listenerPort,
		listenerTlsConf:      listenerTlsConf,
		listenerForceTls:     listenerForceTls,
		listenerDefaultSni:   listenerDefaultSni,
		listenerConfigs:      make(map[string]Sni),
		ctx:                  ctx,
		ctxCancelFunc:        ctxCancel,
		connectionsLogTicker: time.NewTicker(intervalConnectionsLog),
		connectionMap:        cmap.New[*PgConn](),
	}

	// Launch background routine regularly printing currently active connections
	go func() {
		pgProxy.logger.Debugf("Connections logger started.")
		pgProxy.logConnections()
		for {
			select {
			case <-pgProxy.ctx.Done():
				pgProxy.logger.Debugf("Connections logger terminated.")
				return
			case <-pgProxy.connectionsLogTicker.C:
				pgProxy.logConnections()
			}
		}
	}()

	// Return initialized PgProxy
	return &pgProxy, nil
}

// RegisterSni initializes an SNI with a dedicated configuration. The configuration can contain is dedicated
// SSL certificate and custom target database settings. Depending on the server name users will be served
// with specific SSL certificates and forwarded to respective databases.
func (p *PgReverseProxy) RegisterSni(sni ...Sni) error {

	// Iterate SNIs and register them
	for _, s := range sni {

		// Set first one as default one
		if p.listenerDefaultSni && len(p.listenerConfigs) == 0 {
			p.listenerConfigs[""] = s
		}

		// Set sni for common name
		p.listenerConfigs[s.CertificateX509.Subject.CommonName] = s

		// Set sni for subject alternative names
		for _, dns := range s.CertificateX509.DNSNames {
			p.listenerConfigs[dns] = s
		}

		// Set sni for subject alternative IPs
		for _, ip := range s.CertificateX509.IPAddresses {
			p.listenerConfigs[ip.String()] = s
		}
	}

	// Return nil as everything went fine
	return nil
}

// RegisterMonitoring can be used to configure a custom function for user activity logging or monitoring
func (p *PgReverseProxy) RegisterMonitoring(f func(
	loggerClient scanUtils.Logger,
	dbName string,
	dbUser string,
	dbTables []string,
	query string,
	queryResults int,
	queryStart time.Time,
	queryEndExec time.Time,
	queryEndTotal time.Time,
	clientName string,
) error) {
	p.fnMonitoring = f
}

// Stop shuts down the Postgres reverse proxy
func (p *PgReverseProxy) Stop() {

	// Log shutdown
	p.logger.Infof("PgProxy shutting down.")
	if p.connectionCnt > 0 {
		p.logger.Debugf("PgProxy has %d active connections left.", p.connectionCnt)
		p.connectionsLogTicker.Reset(intervalConnectionsLog)
		p.logConnections()
	}

	// Cancel context
	p.ctxCancelFunc()

	// Close listener to interrupt proxied connections
	_ = p.listener.Close()

	// Wait for active connections to be terminated
	p.wg.Wait()
	p.logger.Debugf("PgProxy stopped.")
}

// Serve listens for incoming connections and processes them in an asynchronous goroutine
func (p *PgReverseProxy) Serve() { // Log termination

	// Check if at least one certificate is set
	if len(p.listenerConfigs) == 0 {
		p.logger.Errorf("PgProxy certificates not configured.")
		return
	} else {
		msg := fmt.Sprintf("PgProxy certificates configured on port %d:", p.listenerPort)

		// Iterate listener configs
		for k, v := range p.listenerConfigs {

			// Prepare data
			if k == "" {
				k = "DEFAULT"
			}
			certFingerprint := md5.Sum(v.CertificateX509.Raw)
			subjAltNames := strings.Join(v.CertificateX509.DNSNames, ", ")
			subjAltIps := ""
			for _, ip := range v.CertificateX509.IPAddresses {
				subjAltIps += ip.String() + ", "
			}
			subjAltIps = strings.Trim(subjAltIps, " ")

			// Append message
			msg += fmt.Sprintf("\n    %s:", k)
			msg += fmt.Sprintf("\n          Fingerprint    : %s", hex.EncodeToString(certFingerprint[:]))
			msg += fmt.Sprintf("\n          Common Name    : %s", v.CertificateX509.Subject.CommonName)
			if subjAltNames != "" {
				msg += fmt.Sprintf("\n          Subj Alt Names : %s", subjAltNames)
			}
			if subjAltIps != "" {
				msg += fmt.Sprintf("\n          Subj Alt IPs   : %s", subjAltIps)
			}
			if len(v.AllowedOrigins) > 0 {
				msg += fmt.Sprintf("\n          Allowed Origins: %s", strings.Join(v.AllowedOrigins, ", "))
			}
		}
		p.logger.Debugf(msg)
	}

	// Continuously listen for incoming connections
	for {

		// Accept connection
		client, errClient := p.listener.Accept()
		if errClient != nil {

			// Stop serving if listener got closed
			if errors.Is(errClient, net.ErrClosed) {
				return
			}

			// Ignore timeout errors
			var ne net.Error
			if errors.As(errClient, &ne) && ne.Timeout() {
				p.logger.Infof("Client connection failed: %s.", errClient)
				continue // Continue with next connection attempt
			}

			// Log error
			p.logger.Errorf("Client connection failed: %s.", errClient)
			continue // Continue with next connection attempt
		}

		// Increase connection counter
		p.connectionCnt += 1

		// Handle client connection
		go func() {

			// Decrease counter afterward
			defer func() { p.connectionCnt -= 1 }()

			// Handle connection
			p.handleClient(client)
		}()
	}
}

// handleClient processes a single client connection and proxies communication between a client and a database
func (p *PgReverseProxy) handleClient(client net.Conn) {

	// Add to wait group and make sure it's decremented at the end again
	p.wg.Add(1)
	defer p.wg.Done()

	// Generate UUID for context
	uuid := shortuuid.New()[0:10] // Shorten uuid, doesn't need to be that long

	// Get tagged logger for connection stream
	logger := scanUtils.NewTaggedLogger(p.logger, uuid)

	// Log final message for this interaction
	defer func() { logger.Infof("Proxying communication ended.") }()

	// Close client connection at the end, if still open
	defer func() { _ = client.Close() }()

	// Catch potential panics to gracefully log issue with stacktrace
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, scanUtils.StacktraceIndented("\t")))
		}
	}()

	// Log initial message
	logger.Infof("Client connected from '%s'", client.RemoteAddr())

	// Prepare memory to remember SNI sent by client
	sni := ""

	// Prepare copy of listener config and set GetCertificate to select an applicable certificate based
	// on the SNI indicated by the client hello for local goroutine. Must be a copy to avoid parallel
	// access to local sni variables.
	tlsConf := p.listenerTlsConf.Clone()
	tlsConf.GetCertificate = func(t *tls.ClientHelloInfo) (*tls.Certificate, error) {

		// Store SNI sent by client
		sni = t.ServerName

		// Get listener config based on SNI
		listenerConfig, okListenerConfig := p.listenerConfigs[t.ServerName]
		if !okListenerConfig {
			if t.ServerName == "" {
				return nil, &ErrCertificate{Message: fmt.Sprintf("invalid SNI")}
			} else {
				return nil, &ErrCertificate{Message: fmt.Sprintf("invalid SNI '%s'", t.ServerName)}
			}
		}

		// Return related certificate
		return &listenerConfig.Certificate, nil
	}

	// Set initial deadline for client to complete handshake
	errDeadline := client.SetDeadline(time.Now().Add(time.Second * 10))
	if errDeadline != nil {
		logger.Errorf("Could not set client deadline: %s.", errDeadline)
	}

	// Prepare client backend to receive client messages
	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(client), client)

	// Prepare memory for error message to be transferred to client
	var clientErrMsg *pgconn.PgError

	// Prepare function to notify client
	var notifyClient = func(errPg *pgconn.PgError) {

		// Prepare error response
		errResp := &pgproto3.ErrorResponse{
			Severity:            errPg.Severity,
			SeverityUnlocalized: "",
			Code:                errPg.Code,
			Message:             errPg.Message,
			Detail:              errPg.Detail,
			Hint:                errPg.Hint,
			Position:            errPg.Position,
			InternalPosition:    errPg.InternalPosition,
			InternalQuery:       errPg.InternalQuery,
			Where:               errPg.Where,
			SchemaName:          errPg.SchemaName,
			TableName:           errPg.TableName,
			ColumnName:          errPg.ColumnName,
			DataTypeName:        errPg.DataTypeName,
			ConstraintName:      errPg.ConstraintName,
			File:                errPg.File,
			Line:                errPg.Line,
			Routine:             errPg.Routine,
			UnknownFields:       nil,
		}

		// Log and execute action
		logger.Debugf("Forwarding error response to client.")
		errSend := clientBackend.Send(errResp)
		if errors.Is(errSend, net.ErrClosed) {
			// Connection already closed
		} else if errSend != nil {
			logger.Errorf("Could not return fatal error to client: %s\n%s", errSend, errPg)
		}
	}

	// Let client know about issues with the database on termination
	defer func() { // Wrap in function to use dynamic clientErrMsg, otherwise nil will be compiled
		if clientErrMsg != nil {
			notifyClient(clientErrMsg)
		}
	}()

	// Prepare memory for startup data
	var startupRaw *pgproto3.StartupMessage
	var isSsl = false

	////////////////////////////////////////////////////////////////
	// Read startup messages from client until conditions are agreed
	////////////////////////////////////////////////////////////////
	logger.Debugf("Receiving startup data from client.")
	for startupRaw == nil {

		// Read startup message
		startup, errStartup := clientBackend.ReceiveStartupMessage()
		if errors.Is(errStartup, io.EOF) || errors.Is(errStartup, syscall.ECONNRESET) { // Connection closed by client
			logger.Debugf("Client terminated connection.")
			return
		} else if errStartup != nil {

			// Set error details to be forwarded to client
			clientErrMsg = &pgconn.PgError{
				Code:    "FATAL",
				Message: "Invalid startup message",
			}

			logger.Debugf("Client startup failed: %s.", errStartup)
			return
		}

		switch m := startup.(type) {
		case *pgproto3.StartupMessage:

			// Reject plaintext connections if necessary
			if p.listenerForceTls && !isSsl {

				// Set error details to be forwarded to client
				clientErrMsg = &pgconn.PgError{
					Code:    "FATAL",
					Message: "SSL connection required",
				}

				// Log error and return
				logger.Infof("Client plaintext connection not allowed.")
				return // Abort in case of communication error
			}

			// Keep details from startup message for later
			startupRaw = m

		case *pgproto3.CancelRequest:

			// Prepare cancellation request
			keyData := pgproto3.BackendKeyData{
				ProcessID: m.ProcessID,
				SecretKey: m.SecretKey,
			}

			// Get key
			k := generateKey(&keyData)

			// Get connection to cancel by key
			pgConn, okPgConn := p.connectionMap.Get(k)
			if !okPgConn {
				logger.Infof("Cancel request for unknown connection '%T'.", keyData)
				return // Abort in case of communication error
			}

			// Prepare cancel data
			buf := make([]byte, 16)
			binary.BigEndian.PutUint32(buf[0:4], 16)
			binary.BigEndian.PutUint32(buf[4:8], 80877102)
			binary.BigEndian.PutUint32(buf[8:12], m.ProcessID)
			binary.BigEndian.PutUint32(buf[12:16], m.SecretKey)

			// Send cancel request on connection
			_, errWrite := pgConn.ConnectionDb.Write(buf)
			if errWrite != nil {
				var opError *net.OpError
				if errors.As(errWrite, &opError) {
					// Ignore operational errors
				} else {
					logger.Errorf("Cancel request failed: %s.", errWrite)
					return // Abort in case of communication error
				}
			}

			// Read cancel response from connection
			_, errRead := pgConn.ConnectionDb.Read(buf)
			if errRead != nil {
				var opError *net.OpError
				if errors.As(errWrite, &opError) {
					// Ignore operational errors
				} else if errRead != io.EOF {
					// Ignore read error
				} else {
					logger.Errorf("Cancel response failed: %s.", errRead)
					return // Abort in case of communication error
				}
			}

			// Log success and abort further communication
			logger.Infof("Cancel request successful.")
			return

		case *pgproto3.SSLRequest:

			// Reject SSL encryption request, if not desired
			if tlsConf == nil {

				// Reject SSL encryption request
				_, errWrite := client.Write([]byte{'N'})
				if errWrite != nil {
					logger.Errorf("Client startup failed: could not reject SSL request.")
					return // Abort in case of communication error
				}

				// Continue with next startup message
				break
			}

			// Set SSL flag
			isSsl = true

			// Upgrade to SSL encrypted channel
			_, errWrite := client.Write([]byte{'S'})
			if errWrite != nil {
				logger.Errorf("Client startup failed: could not accept SSL request.")
				return // Abort in case of communication error
			}

			// Execute SSL handshake
			var errCertificate *ErrCertificate
			clientTls := tls.Server(client, tlsConf)
			errClientTls := clientTls.Handshake()
			if errors.Is(errClientTls, io.EOF) || errors.Is(errClientTls, net.ErrClosed) ||
				errors.Is(errClientTls, syscall.ECONNRESET) || errors.Is(errClientTls, os.ErrDeadlineExceeded) { // Connection closed by client
				_ = clientTls.Close()
				logger.Debugf("Client terminated connection.")
				return
			} else if errors.As(errClientTls, &errCertificate) {

				// Prepare error to return to the client
				clientErrMsg = &pgconn.PgError{
					Code:    "FATAL",
					Message: "SSL connection with " + errCertificate.Error(),
				}

				// Log issue and return
				_ = clientTls.Close()
				logger.Infof("Client startup failed during SSL handshake: %s.", errClientTls)
				return
			} else if errClientTls != nil {
				_ = clientTls.Close()
				logger.Infof("Client startup failed: could not execute SSL handshake: %s.", errClientTls)
				return // Abort in case of communication error
			}

			// Upgrade client backend to receive future client messages
			clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(clientTls), clientTls)

		case *pgproto3.GSSEncRequest:

			// Reject GSS encryption request
			_, errWrite := client.Write([]byte{'N'})
			if errWrite != nil {
				logger.Errorf("Client startup failed: could not reject GSS request.")
				return // Abort in case of communication error
			}

		default:

			// Log unexpected startup sequence
			logger.Errorf("Client startup failed: unexpected type '%T'.", startup)
			return // Abort in case of communication error

		}
	}

	// Check if client can be dispatched to suitable listener configuration
	if !p.listenerDefaultSni && sni == "" {
		if isSsl {

			// Prepare error to return to the client
			clientErrMsg = &pgconn.PgError{
				Code:    "FATAL",
				Message: "SSL connection requires SNI data",
			}

			// Log situation and return
			logger.Infof("Client connection without SNI cannot be dispatched, there is no default database server.")
			return
		} else {

			// Prepare error to return to the client
			clientErrMsg = &pgconn.PgError{
				Code:    "FATAL",
				Message: "SSL connection with SNI required",
			}

			// Log situation and return
			logger.Infof("Client connection without SSL/SNI cannot be dispatched, there is no default database server.")
			return
		}
	}

	// Log target database derived from connection settings
	if !isSsl {
		logger.Debugf("Client connection without SSL dispatching to DEFAULT database server.")
	} else if sni == "" {
		logger.Debugf("Client connection without SNI dispatching to DEFAULT database server.")
	} else {
		logger.Debugf("Client connection dispatching to database server '%s'.", sni)
	}

	// Log user requesting connection
	logger.Debugf("Client connection to '%s' as '%s'.", startupRaw.Parameters["database"], startupRaw.Parameters["user"])

	// Request password from client
	logger.Debugf("Requesting authentication password from client.")
	errClientSend := clientBackend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if errClientSend != nil {
		logger.Errorf("Client startup failed: could not request password: %s.", errClientSend)
		return // Abort in case of communication error
	}

	// Receive password from client
	responseAuth, errResponseAuth := clientBackend.Receive()
	if errors.Is(errResponseAuth, io.ErrUnexpectedEOF) { // Connection closed by client
		logger.Debugf("Client terminated connection.")
		return
	} else if errResponseAuth != nil {
		logger.Errorf("Client startup failed: could not receive password: %s.", errResponseAuth)
		return // Abort in case of communication error
	}

	// Cast response to type PasswordMessage
	startupPassword, ok := responseAuth.(*pgproto3.PasswordMessage)
	if !ok {
		logger.Errorf("Client startup failed: unexpected password response: %T.", responseAuth)
		return // Abort in case of communication error
	}

	///////////////////////////////////////
	// Connect to database for proxy client
	///////////////////////////////////////

	// Prepare database target address
	listenerConfig, okListenerConfig := p.listenerConfigs[sni]
	if !okListenerConfig {
		logger.Errorf("Database startup failed: no database server configuration for SNI '%s'.", sni)
		return // Abort in case of communication error
	}

	// Extract IP from remote address
	host, _, errHost := net.SplitHostPort(client.RemoteAddr().String())
	if errHost != nil {
		logger.Errorf("Client startup failed: could not parse remote address '%s'.", client.RemoteAddr().String())
		return
	}

	// Check if origin IP is allowed
	if len(listenerConfig.AllowedOrigins) > 0 &&
		!scanUtils.StrContained(host, listenerConfig.AllowedOrigins) {

		// Set error details to be forwarded to client
		clientErrMsg = &pgconn.PgError{
			Code:    "FATAL",
			Message: "Connection with invalid origin",
		}

		// Log error and return
		logger.Infof("Client startup failed: Invalid origin '%s' for SNI.", host)
		return // Abort in case of communication error
	}

	// Log database selection
	logger.Debugf("Proxying to database server '%s'.", listenerConfig.Database.Host)

	// Build address for connection
	address := fmt.Sprintf("%s:%d", listenerConfig.Database.Host, listenerConfig.Database.Port)

	// Dial backend based on startup data
	connDatabase, errDatabase := net.Dial("tcp", address)
	if errDatabase != nil {

		// Set error details to be forwarded to client
		clientErrMsg = &pgconn.PgError{
			Code:    "FATAL",
			Message: errDatabase.Error(),
		}

		// Log error and return
		logger.Errorf("Database startup failed: could not connect to database server '%s': %s.", address, errDatabase)
		return // Abort in case of communication error
	}

	// Close database connection at the end, if still open
	defer func() { _ = connDatabase.Close() }()

	// Prepare database frontend to receive database messages
	databaseReader := pgproto3.NewChunkReader(connDatabase)
	databaseFrontend := pgproto3.NewFrontend(databaseReader, connDatabase)

	/////////////////////////////////////////////////
	// Upgrade database connection to SSL, if desired
	/////////////////////////////////////////////////
	if listenerConfig.Database.SslMode != "disable" {

		// Decide whether to verify the encrypted connection
		skipVerify := false
		if scanUtils.StrContained(listenerConfig.Database.SslMode, []string{"allow", "prefer", "require"}) {
			skipVerify = true
		}

		// Prepare TLS config for database connection
		tlsDatabase := &tls.Config{
			ServerName:         listenerConfig.Database.Host,
			InsecureSkipVerify: skipVerify,
		}

		// Log SSL initialization
		logger.Debugf("Upgrading database connection to SSL.")

		// Send SSL request
		errDatabaseSend := databaseFrontend.Send(&pgproto3.SSLRequest{})
		if errDatabaseSend != nil {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log error and return
			logger.Errorf("Database startup failed: could not send SSL request: %s.", errDatabaseSend)
			return // Abort in case of communication error
		}

		// Read SSL response
		rDatabase, errDatabaseR := databaseReader.Next(1)
		if errDatabaseR != nil {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log error and return
			logger.Errorf("Database startup failed: could not read SSL response: %s.", errDatabaseR)
			return // Abort in case of communication error
		}

		// Process database response
		if rDatabase[0] == 'N' {

			if listenerConfig.Database.SslMode == "require" {

				// Set error details to be forwarded to client
				clientErrMsg = ErrInternal

				// Log SSL rejection and abort
				logger.Errorf("Database startup failed: SSL connection rejected.")
				return // Abort in case of communication error

			} else {

				// Log SSL rejection and CONTINUE with plaintext connection
				logger.Infof("Database rejected SSL request, proceeding without encryption!")
			}

		} else if rDatabase[0] == 'S' {

			// Execute SSL handshake
			databaseTls := tls.Client(connDatabase, tlsDatabase)
			errDatabaseTls := databaseTls.Handshake()
			if errDatabaseTls != nil {
				_ = databaseTls.Close()

				// Set error details to be forwarded to client
				clientErrMsg = ErrInternal

				// Log error and return
				logger.Errorf("Database startup failed: could not execute SSL handshake: %s.", errDatabaseTls)
				return // Abort in case of communication error
			}

			// Upgrade database frontend to receive future client messages
			databaseFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(databaseTls), databaseTls)

		} else if rDatabase[0] == 'E' {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Read error header
			header, errHeader := databaseReader.Next(4)
			if errHeader != nil {
				logger.Errorf("Database startup failed: could not read SSL error header: %s.", errHeader)
				return // Abort in case of communication error
			}

			// Read error message
			length := int(binary.BigEndian.Uint32(header)) - 4
			message, errMessage := databaseReader.Next(length)
			if errMessage != nil {
				logger.Errorf("Database startup failed: could not read SSL error message: %s.", errMessage)
				return // Abort in case of communication error
			}

			// Decode error message
			var messageDecoded pgproto3.ErrorResponse
			errDecode := messageDecoded.Decode(message)
			if errDecode != nil {
				logger.Errorf("Database startup failed: could not decode SSL error message: %s.", errDecode)
				return // Abort in case of communication error
			}

			// Log negotiation error and abort
			logger.Errorf(
				"Database startup failed: could not negotiate SSL: %s (%s).",
				messageDecoded.Message,
				messageDecoded.Code,
			)
			return // Abort in case of communication error

		} else {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log unexpected response and abort
			logger.Errorf("Database startup failed: unexpected negotiation response '%v'.", rDatabase[0])
			return // Abort in case of communication error
		}
	}

	////////////////////////////////////////////////////////////////
	// Initialize database connection using startup data from client
	////////////////////////////////////////////////////////////////
	logger.Debugf("Initializing database connection.")

	// Forward client startup data to database
	errDatabaseSend := databaseFrontend.Send(startupRaw)
	if errDatabaseSend != nil {

		// Set error details to be forwarded to client
		clientErrMsg = ErrInternal

		// Log error and return
		logger.Errorf("Database startup failed: could not send startup message: %s.", errDatabaseSend)
		return // Abort in case of communication error
	}

	// Authenticate on database using details from client
	logger.Debugf("Authenticating database connection.")
	do := true
	for do {

		// Read startup response
		responseStartup, errResponseStartup := databaseFrontend.Receive()
		if errResponseStartup != nil {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log error and return
			logger.Errorf("Database startup failed: could not receive startup response: %s.", errResponseStartup)
			return
		}

		switch m := responseStartup.(type) {
		case *pgproto3.AuthenticationOk:

			// Exit startup loop after successful negotiation
			do = false

		case *pgproto3.AuthenticationCleartextPassword:

			// Send Password in cleartext
			errSend := databaseFrontend.Send(startupPassword)
			if errSend != nil {

				// Set error details to be forwarded to client
				clientErrMsg = ErrInternal

				// Log error and return
				logger.Errorf("Database cleartext authentication failed: %s.", errSend)
				return // Abort in case of communication error
			}

		case *pgproto3.AuthenticationMD5Password:

			// Prepare MD5
			salt := string(m.Salt[:])
			user := startupRaw.Parameters["user"]
			pass := startupPassword.Password
			checksum1 := md5.Sum([]byte(pass + user))
			checksum2 := md5.Sum([]byte(hex.EncodeToString(checksum1[:]) + salt))
			passwordMd5 := "md5" + hex.EncodeToString(checksum2[:])

			// Send Password as MD5
			errSend := databaseFrontend.Send(&pgproto3.PasswordMessage{Password: passwordMd5})
			if errSend != nil {

				// Set error details to be forwarded to client
				clientErrMsg = ErrInternal

				// Log error and return
				logger.Errorf("Database MD5 authentication failed: %s.", errSend)
				return // Abort in case of communication error
			}

		case *pgproto3.AuthenticationSASL:

			// Send SASL authentication
			errSend := saslAuth(databaseFrontend, startupPassword.Password, m.AuthMechanisms)
			if errSend != nil {

				// Check for authentication errors and handle them accordingly
				var e *pgconn.PgError
				if errors.As(errSend, &e) {

					// Set error details to be forwarded to client
					clientErrMsg = e

					// Log error and return
					logger.Infof("Database SASL authentication failed: %s.", e.Message)
					return
				}

				// Set error details to be forwarded to client
				clientErrMsg = ErrInternal

				// Log error and return
				logger.Errorf("Database SASL authentication failed: %s.", errSend)
				return
			}

		case *pgproto3.ErrorResponse:

			// Set error details to be forwarded to client
			clientErrMsg = pgconn.ErrorResponseToPgError(m)

			// Log error and return
			logger.Infof("Database authentication failed: %s.", m.Message)
			return // Abort in case of communication error

		default:

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log unexpected response
			logger.Errorf("Database authentication failed: unexpected response '%T'.", m)
			return // Abort in case of communication error

		}
	}

	//////////////////////
	// Authenticate client
	//////////////////////
	logger.Debugf("Forwarding authentication result to client.")

	// Respond to client with AuthTypeOk
	_ = clientBackend.SetAuthType(pgproto3.AuthTypeOk)
	errClientSend = clientBackend.Send(&pgproto3.AuthenticationOk{})
	if errClientSend != nil {

		// Set error details to be forwarded to client
		clientErrMsg = ErrInternal

		// Log error and return
		logger.Errorf("Client authentication failed: could not return 'AuthenticationOk': %s.", errClientSend)
		return // Abort in case of communication error
	}

	///////////////////////////////////////////////////////////////////////////////
	// Finalize handshake with client using backend key data from database, if sent
	///////////////////////////////////////////////////////////////////////////////
	logger.Debugf("Forwarding final handshake messages to client.")

	// Prepare memory for key data from database
	var keyData *pgproto3.BackendKeyData

	// Read messages from database and copy to client until connection is 'ReadyForQuery'
	for {

		// Read from database
		response, errResponse := databaseFrontend.Receive()
		if errResponse != nil {

			// Set error details to be forwarded to client
			clientErrMsg = &pgconn.PgError{
				Code:    "FATAL",
				Message: errResponse.Error(),
			}

			// Log error and return
			logger.Errorf("Client handshake failed: could not receive: %s.", errResponse)
			return // Abort in case of communication error
		}

		// Check if response is error response
		if err, isErr := response.(*pgproto3.ErrorResponse); isErr {

			// Set error details to be forwarded to client
			clientErrMsg = pgconn.ErrorResponseToPgError(err)

			// Log error and return
			logger.Infof("Client handshake failed: %s.", err.Message)
			return // Abort in case of communication error
		}

		// Copy to database
		errSend := clientBackend.Send(response)
		if errSend != nil {

			// Set error details to be forwarded to client
			clientErrMsg = ErrInternal

			// Log error and return
			logger.Errorf("Client handshake failed: could not forward: %s.", errSend)
			return // Abort in case of communication error
		}

		// Check for response type and exit loop if 'ReadyForQuery'
		if data, isKey := response.(*pgproto3.BackendKeyData); isKey {

			// Copy values of Receive() to key data for later usage
			keyDataCopy := *data
			keyData = &keyDataCopy

		} else if _, isReady := response.(*pgproto3.ReadyForQuery); isReady {

			// Break loop as connection is now ready for query
			break
		}
	}

	///////////////////////////////////////////////////////////////////////
	// Cache connections for later lookups, e.g. to execute cancel requests
	///////////////////////////////////////////////////////////////////////
	logger.Debugf("Connection PID: %d.", keyData.ProcessID)
	logger.Debugf("Connection SID: %d.", keyData.SecretKey)
	logger.Infof("Caching connection details.")

	// Cache key data and associated database connection if available
	k := uuid // Chose random value if no key data is available
	if keyData != nil {
		k = generateKey(keyData)
	}

	// Prepare PgCon data for this connection
	pgConn := PgConn{
		Uuid:             uuid,
		Pid:              keyData.ProcessID, // Might be 0 if no key data is available
		Sid:              keyData.SecretKey, // Might be 0 if no key data is available
		Db:               startupRaw.Parameters["database"],
		User:             startupRaw.Parameters["user"],
		Application:      startupRaw.Parameters["application_name"],
		Timestamp:        time.Now(),
		ConnectionDb:     connDatabase,
		ConnectionClient: client,
	}

	// Store connection under key
	p.connectionMap.Set(k, &pgConn)

	// Make sure entry is cleaned from map after database connection is terminated
	defer func() {
		logger.Debugf("Removing cached connection details.")
		p.connectionMap.Remove(k)
	}()

	// Print current connections
	p.connectionsLogTicker.Reset(intervalConnectionsLog)
	p.logConnections()

	/////////////////////////////////////////////////////////////
	// Proxy continuous communication between client and database
	/////////////////////////////////////////////////////////////
	logger.Infof("Proxying communication between client and database.")

	// Prepare done channel to terminate goroutines
	chDone := make(chan struct{}, 2)
	defer close(chDone)

	// Prepare wait group to wait for remaining goroutines
	wg := new(sync.WaitGroup)

	// Prepare buffered channel for communication between query and response
	type Statement struct {
		Query      string
		QueryInput string // Original query sent by client, which Query is extracted from
		Start      time.Time
	}

	// Prepare slice to recorde the sequence of queries sent to the database.
	// This slice can be used to map later database responses to their original query request.
	var statementSequence []*Statement

	// Disable client timeout, client might hold connection ready.
	errDeadline = client.SetDeadline(time.Time{})
	if errDeadline != nil {
		p.logger.Errorf("Could not reset client deadline: %s.", errDeadline)
	}

	// Listen for client requests
	go func() {

		// Log termination
		defer func() { logger.Debugf("Client receiver terminated.") }()

		// Indicate end of communication to unblock parent goroutine
		defer func() { chDone <- struct{}{} }()

		// Increase wait group and make sure to decrease on termination
		wg.Add(1)
		defer wg.Done()

		// Catch potential panics to gracefully log issue with stacktrace
		defer func() {

			// Log issue
			if r := recover(); r != nil {
				logger.Errorf(fmt.Sprintf("Panic: %s%s", r, scanUtils.StacktraceIndented("\t")))
			}
		}()

		// Prepare cache to lookup previously defined prepared statements (queries).
		// In extended query flow the Bind message might reference previously defined queries.
		var statementCache = make(map[string]string)

		// Loop and listen for client requests
		for {

			// Receive from client
			r, errR := clientBackend.Receive()
			if errR != nil {

				// Log error with respective criticality
				var opError *net.OpError
				if errors.Is(errR, io.ErrUnexpectedEOF) { // Connection closed by client
					logger.Debugf("Client terminated connection.")
				} else if errors.Is(errR, os.ErrDeadlineExceeded) { // Connection closed by PgProxy because client was inactive
					logger.Infof("Client connection terminated due to inactivity.")
				} else if errors.Is(errR, net.ErrClosed) { // Connection closed by PgProxy
					// Connection closed by PgProxy
				} else if errors.As(errR, &opError) {
					logger.Infof("Client connection terminated: %s", opError)
				} else { // Unexpected error
					logger.Errorf("Proxying data from client failed: %s.", errR)
				}

				// Return and end client receiver
				return
			}

			// Forwarding query data to database receiver routine
			if p.fnMonitoring != nil {

				// Prepare data
				switch q := r.(type) {
				case *pgproto3.Query:

					// Split multi-query into single SQL statements
					queries := splitQueries(q.String)

					// Log action
					if len(queries) == 1 {
						logger.Debugf("Request  Type '%T', adding query to statement sequence.", r)
					} else if len(queries) > 1 {
						logger.Debugf("Request  Type '%T', adding %d queries to statement sequence.", r, len(queries))
					}

					// Add query to statement sequence
					for _, query := range queries {
						statementSequence = append(statementSequence, &Statement{
							Query:      query,
							QueryInput: q.String,
							Start:      time.Now(),
						})
					}

					// Switch connection state to active
					if len(queries) > 0 {
						pgConn.TimestampLast = time.Now()
						pgConn.QueryInProgress = true
					}

				case *pgproto3.Parse:
					logger.Debugf("Request  Type '%T', registering query.", r)

					// Add query to prepared statement cache
					statementCache[q.Name] = trimEmptySyntax(q.Query)

				case *pgproto3.Bind: // Client requesting to execute a previously parsed/prepared statement
					logger.Debugf("Request  Type '%T', adding query to statement sequence.", r)

					// Retrieve associated query from statement cache
					query, okQuery := statementCache[q.PreparedStatement]
					if !okQuery {
						logger.Errorf("Reference '%s' not existing in statement cache.", q.PreparedStatement)
					}

					// Add query to statement sequence
					statementSequence = append(statementSequence, &Statement{
						Query:      query,
						QueryInput: query,
						Start:      time.Now(),
					})

					// Switch connection state to active
					pgConn.TimestampLast = time.Now()
					pgConn.QueryInProgress = true

				default:
					logger.Debugf("Request  Type '%T'.", r)
				}

				// Log branch completion, to see whether something got stuck
				logger.Debugf("Request  Type '%T' done.", r)
			}

			// Forward to database
			errSend := databaseFrontend.Send(r)
			if errSend != nil {

				// Log error
				logger.Errorf("Proxying data to database failed: %s.", errSend)

				// Notify client about issue with backend database
				notifyClient(&pgconn.PgError{
					Code:    "FATAL",
					Message: errSend.Error(),
				})

				// Return and end client receiver
				return
			}

			// Exit goroutine if necessary
			select {
			case <-p.ctx.Done():
				return
			default:
			}
		}
	}()

	// Listen for database responses
	go func() {

		// Log termination
		defer func() { logger.Infof("Database receiver terminated.") }()

		// Indicate end of communication to unblock parent goroutine
		defer func() { chDone <- struct{}{} }()

		// Increase wait group and make sure to decrease on termination
		wg.Add(1)
		defer wg.Done()

		// Prepare process variables
		var statement = 0               // Current SQL statement pointer in a sequence of statements
		var statementRows = 0           // Amount of rows returned by an SQL statement
		var statementDone = time.Time{} // Timestamp when the statement finished executing (before transmission)

		// Catch potential panics to gracefully log issue with stacktrace
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf(fmt.Sprintf("Panic: %s%s", r, scanUtils.StacktraceIndented("\t")))
			}
		}()

		// Check if there were remaining queries at the end and warn about for debugging purposes
		defer func() {
			if statement < len(statementSequence) {

				// Extract queries from remaining statements
				remainingQueries := make([]string, 0, len(statementSequence)-statement)
				for _, remainingQuery := range statementSequence[statement:] {
					remainingQueries = append(remainingQueries, remainingQuery.Query)
				}

				// Log remaining statements
				// There should be zero left, amount of requests should exactly match amount of responses,
				// otherwise, the monitoring function might point to wrong statement queries causing invalid logs!
				logger.Errorf(
					"Responses did not match requests and are off by %d (%d total):\n%s",
					len(statementSequence)-statement,
					len(statementSequence),
					strings.Join(remainingQueries, ";\n"),
				)
			}
		}()

		// Loop and listen for database responses
		for {

			// Receive from database
			r, errR := databaseFrontend.Receive()
			if errR != nil {

				// Log error with respective criticality
				if errors.Is(errR, io.ErrUnexpectedEOF) { // Connection closed by database
					logger.Infof("Database terminated connection: %s.", errR)
				} else if errors.Is(errR, net.ErrClosed) { // Connection closed by PgProxy
					// Connection closed by PgProxy
				} else { // Unexpected error
					logger.Errorf("Proxying data from server failed: %s.", errR)

					// Notify client about issue with backend database
					notifyClient(&pgconn.PgError{
						Code:    "FATAL",
						Message: errR.Error(),
					})
				}

				// Return and end database receiver
				return
			}

			// Execute statement monitoring if activated
			if p.fnMonitoring != nil {

				// Act on response depending on type
				switch resp := r.(type) {
				case *pgproto3.ErrorResponse:

					// Get associated query
					query := ""
					queryInput := ""
					if statement < len(statementSequence) {
						query = statementSequence[statement].Query
						queryInput = statementSequence[statement].QueryInput
					} else {
						logger.Errorf("Statement %d does not exist in statement sequence.", statement)
					}

					// Try to prettify query if possible {
					if resp.Code == "42601" { // Syntax error
						// Fall back to the complete query input from the client
						// The database is parsing the whole multi-query SQL string and checking its syntax
						// before executing each of the contained queries. In case of a syntax error the
						// database only returns once and the syntax error might not necessarily need to
						// be contained in the first of the many queries.
						query = queryInput
					} else { // No syntax error
						_, query = prettify(logger, query) // Try to prettify
					}

					// Log response type
					logger.Debugf(
						"Response Type '%T': %s\n%s\n%s",
						resp,
						resp.Message,
						spew.Sdump(resp),
						"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
					)

					// Skip subsequent already known queries, because they will be
					// skipped by the database after this error
					statement = len(statementSequence)

				case *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended: // Responses from empty query strings

					// Postgres returns EmptyQueryResponse if there was nothing to execute
					logger.Debugf("Response Type '%T'.", resp)

					// Release memory of statement, it's not needed anymore
					// Do not reset whole statementSequence because subsequent queries might already be queued!
					statementSequence[statement] = nil

					// Increment statement pointer
					statement++

					// Reset statement's response row counter
					statementRows = 0

					// Reset query time for new timing
					statementDone = time.Time{}

				case *pgproto3.RowDescription:

					// Postgres returns one RowDescription response per statement result
					logger.Debugf("Response Type '%T'.", resp)
					statementDone = time.Now()

				case *pgproto3.DataRow:

					// Postgres returns one DataRow response per result ROW!
					// Don't log, because it would bloat the log file.
					statementRows++

				case *pgproto3.CommandComplete:

					// Make up for skipped DataRow response logs with aggregated DataRow log entry
					if statementRows > 0 {
						logger.Debugf("Response Type '%T' (%dx).", &pgproto3.DataRow{}, statementRows)
					}

					// Log action
					logger.Infof("Response Type '%T', logging statement.", resp)

					// Get associated query data
					queryData := statementSequence[statement]

					// Get query, prettify and unify for logging
					tables, query := prettify(logger, queryData.Query)

					// Extract row count
					queryRows := parseRows(logger, resp.CommandTag)

					// Log statement execution
					tEnd := time.Now()
					tExec := tEnd
					if !statementDone.IsZero() {
						tExec = statementDone
					}
					errMonitoring := p.fnMonitoring(
						logger,
						startupRaw.Parameters["database"],
						startupRaw.Parameters["user"],
						tables,
						query,
						queryRows,
						queryData.Start,
						tExec,
						tEnd,
						startupRaw.Parameters["application_name"],
					)
					if errMonitoring != nil {
						logger.Errorf("Could not monitor query: %s.", errMonitoring)
					}

					// Release memory of statement, it's not needed anymore
					// Do not reset whole statementSequence because subsequent queries might already be queued!
					statementSequence[statement] = nil

					// Increment statement pointer
					statement++

					// Reset statement's response row counter
					statementRows = 0

					// Reset query time for new timing
					statementDone = time.Time{}

				case *pgproto3.ParameterStatus: //  Informs the frontend about the current (initial) setting of a backend parameter

					// Might be sent by the backend automatically AFTER CommandComplete
					// (e.g. if notification of client after SET statement is intended)
					logger.Debugf("Response Type '%T', backend set '%s' to '%s'.", resp, resp.Name, resp.Value)

					// Update application name in startup data and active connections
					if resp.Name == "application_name" && resp.Value != "" {

						// Update application name in startup parameters
						startupRaw.Parameters["application_name"] = resp.Value

						// Switch connection state to passive
						pgConn.Application = resp.Value
					}

				case *pgproto3.ReadyForQuery:

					// Log action
					logger.Debugf("Response Type '%T'.", resp)

					// Switch connection state to passive
					pgConn.QueryInProgress = false

				default:
					logger.Debugf("Response Type '%T'.", resp)
				}
			}

			// Forward to client
			errSend := clientBackend.Send(r)
			if errSend != nil {

				// Log error with respective criticality
				if errors.Is(errR, os.ErrDeadlineExceeded) { // Connection closed by PgProxy because client was inactive
					logger.Infof("Client connection terminated due to inactivity.")
				} else { // Unexpected error
					logger.Errorf("Proxying data to client failed: %s.", errSend)
				}

				// Return and end database receiver
				return
			}

			// Exit goroutine if necessary
			select {
			case <-p.ctx.Done():
				return
			default:
			}
		}
	}()

	// Wait until communication ended or PgProxy got stopped
	func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			case _ = <-chDone:
				return
			}
		}
	}()

	// Log waiting
	logger.Debugf("Waiting for remaining receiver.")

	// Close client and database connections to resolve potentially blocking Receive() calls in goroutines
	_ = connDatabase.Close()
	_ = client.Close()

	// Read remaining done signal to unblock remaining receiver goroutine. There are always two,
	// one listening for client communication and one listening for database communication.
	<-chDone

	// Wait for all goroutines
	wg.Wait()
}

// logConnections prints currently active connections utilizing the logger
func (p *PgReverseProxy) logConnections() {
	msg := "Active database connections:"
	if p.connectionMap.Count() > 0 {

		// Get current map items as slice
		items := make([]*PgConn, 0, p.connectionMap.Count())
		for _, v := range p.connectionMap.Items() {
			items = append(items, v)
		}

		// Sort slice
		slices.SortFunc(items, func(a, b *PgConn) int {
			if a.Db == b.Db {
				return cmp.Compare(a.User, b.User)
			}
			return cmp.Compare(a.Db, b.Db)
		})

		// Build log message
		for _, v := range items {
			user := v.User
			if len(user) > 20 {
				user = user[:17] + "..."
			}
			client := v.Application
			if len(client) > 25 {
				client = client[:22] + "..."
			}
			last := v.Timestamp
			if !v.TimestampLast.IsZero() {
				last = v.TimestampLast
			}
			state := "Pssv"
			if v.QueryInProgress {
				state = "Actv"
			}
			addr := v.ConnectionClient.RemoteAddr().String()
			host, _, err := net.SplitHostPort(addr)
			if err == nil {
				addr = host
			}
			msg += fmt.Sprintf(
				"\n    [%s] | Last: %-19s (%s) | Db: %-10s | Usr: %-20s | Client: '%-25s' | Src: %-15s",
				v.Uuid,
				last.Format("2006-01-02 15:04:05"),
				state,
				v.Db,
				user,
				client,
				addr,
			)
		}

		// Log message
		p.logger.Debugf(msg)
	} else {
		msg += fmt.Sprintf(" %d", p.connectionCnt)
		p.logger.Debugf(msg)
	}
}

// generateKey is a helper function for uniformity, generating a backend key data identifier string
func generateKey(keyData *pgproto3.BackendKeyData) string {
	return fmt.Sprintf("%d-%d", keyData.ProcessID, keyData.SecretKey)
}

// saslAuth is an adapted version of github.com/jackc/pgconn (auth_scram.go) making it return proper error details.
func saslAuth(fe *pgproto3.Frontend, password string, serverAuthMechanisms []string) error {

	// Initialize new scram client for authentication
	sc, errSc := newScramClient(serverAuthMechanisms, password)
	if errSc != nil {
		return errSc
	}

	// Send client-first-message in a SASLInitialResponse
	saslInitialResponse := &pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          sc.clientFirstMessage(),
	}
	if errSend := fe.Send(saslInitialResponse); errSend != nil {
		return errSend
	}

	// Receive server-first-message payload in a AuthenticationSASLContinue.
	msg, errMsg := fe.Receive()
	if errMsg != nil {
		return errMsg
	}

	// Check for expected AuthenticationSASLContinue message
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASLContinue:
		errSc = sc.recvServerFirstMessage(m.Data)
		if errSc != nil {
			return errSc
		}
	case *pgproto3.ErrorResponse:
		return pgconn.ErrorResponseToPgError(m)
	default:
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", m)
	}

	// Send client-final-message in a SASLResponse
	saslResponse := &pgproto3.SASLResponse{
		Data: []byte(sc.clientFinalMessage()),
	}
	if errSendResp := fe.Send(saslResponse); errSendResp != nil {
		return errSendResp
	}

	// Receive server-final-message payload in a AuthenticationSASLFinal.
	msg2, errMsg2 := fe.Receive()
	if errMsg2 != nil {
		return errMsg2
	}

	// Return authentication issues
	switch m := msg2.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		return sc.recvServerFinalMessage(m.Data)
	case *pgproto3.ErrorResponse:
		return pgconn.ErrorResponseToPgError(m)
	default:
		return fmt.Errorf("expected AuthenticationSASLFinal, got %T", m)
	}
}

// splitQueries checks whether a query consists out of multiple single queries, indicated by a semicolon,
// to be executed by the database. Returns a slice of queries. Queries are sanitized by empty leading or trailing
// symbols. Empty queries are removed. If there is no useful query content at all, an empty slice is returned
func splitQueries(sql string) []string {

	// Cleanup empty characters from both ends
	sql = trimEmptySyntax(sql)

	// Define parse states
	const ( // iota is reset to 0
		CommentNone             = 0
		CommentMaybe            = iota
		CommentLine             = iota
		CommentMultiline        = iota
		CommentMultilineClosing = iota
	)

	// Prepare memory for field func states
	commentState := CommentNone
	quotedSingle := false
	quotedDouble := false

	// Split queries by semicolon if it does not occure within single quotes, double quotes or any kind of comment
	queries := strings.FieldsFunc(sql, func(r rune) bool {

		// Manage opening/closing of line comment
		if commentState == CommentNone {
			if r == '/' || r == '-' {
				commentState = CommentMaybe
			}
		} else if commentState == CommentMaybe {
			if r == '/' || r == '-' {
				commentState = CommentLine
			} else if r == '*' {
				commentState = CommentMultiline
			} else if r != '/' {
				commentState = CommentNone
			}
		} else if commentState == CommentLine {
			if r == '\n' {
				commentState = CommentNone
			}
		} else if commentState == CommentMultiline {
			if r == '*' {
				commentState = CommentMultilineClosing
			}
		} else if commentState == CommentMultilineClosing {
			if r == '/' {
				commentState = CommentNone
			} else if r != '*' {
				commentState = CommentMultiline // Fall back, multi line comment is not yet closing
			}
		}

		// If not commented, check if quoted string starts
		if commentState <= CommentMaybe {

			// Manage opening/closing of double quote strings
			if r == '"' && !quotedSingle {
				quotedDouble = !quotedDouble
			}

			// Manage opening/closing of single quote strings
			if r == '\'' && !quotedDouble {
				quotedSingle = !quotedSingle
			}
		}

		// Return true if character unquoted and uncommented semicolon
		return r == ';' &&
			!quotedSingle &&
			!quotedDouble &&
			commentState != CommentLine &&
			commentState != CommentMultiline
	})

	// Sanitize split queries and remove empty ones
	queriesSanitized := make([]string, 0, len(queries))
	for _, query := range queries {
		query = trimEmptySyntax(query)
		if strings.ReplaceAll(strings.ReplaceAll(query, "\n", ""), " ", "") != "" {
			queriesSanitized = append(queriesSanitized, query)
		}
	}

	// Return split queries
	return queriesSanitized
}

// trimEmptySyntax trims a given character set from the beginning and end of a
// string and repeats until no changes are detected anymore
func trimEmptySyntax(s string) string {
	lengthPrev := 0
	for {
		s = strings.Trim(s, " \n\t") // Remove all leading and trailing characters that do not have a meaning
		if len(s) == lengthPrev {
			return s
		}
		lengthPrev = len(s)
	}
}

// prettify returns a formatted SQL query string and a list of database tables it is targeting. An SQL query
// does not necessarily need to target a table. Also, it might target multiple ones via subqueries.
func prettify(logger scanUtils.Logger, query string) (tables []string, sql string) {

	// Unify spacings in the query
	query = strings.ReplaceAll(query, "    ", "  ") // Replace quad spaces with double spaces
	query = strings.ReplaceAll(query, "\t", "  ")   // Replace tabulators with double spaces
	query = trimEmptySyntax(query)

	// Return empty results if string is empty
	if len(query) == 0 {
		return
	}

	// Check if query contains some indentation already
	indentation := -1
	lines := strings.Split(query, "\n")
	for _, line := range lines {

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Check if this is a line with less indentation
		leadingSpaces := len(line) - len(strings.TrimLeft(line, " "))
		if indentation == -1 || leadingSpaces < indentation {
			indentation = leadingSpaces
		}

		// Break if no indentation found
		if indentation == 0 {
			break
		}
	}

	// Remove potentially existing indentation from each line
	if indentation > 0 {
		for i := 0; i < len(lines); i++ {
			if len(lines[i]) > indentation { // Might be empty line
				lines[i] = lines[i][indentation:]
			}
		}
		query = strings.Join(lines, "\n")
	}

	// Prepare warn flag to avoid duplicate reporting
	warned := false

	// Tokenize query
	tokens, errTokenizer := lexer.Tokenize(query)
	if errTokenizer != nil {
		warned = true
		logger.Warningf(
			"Could not tokenize query: %s:\n%s",
			errTokenizer,
			"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
		)
		// Warn about issue, but continue
	}

	// Search token tree for FROM tables names
	tables = findTableNames(tokens)

	// Prepare formatter options
	options := formatters.DefaultOptions()

	// Parse query clauses from tokens
	tokensParsed, errParse := parser.Parse(tokens, options)
	if errParse != nil && !warned {
		warned = true
		logger.Warningf(
			"Could not parse query: %s:\n%s",
			errParse,
			"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
		)
		// Warn about issue, but continue
	}

	// Format parsed tokens into buffer
	var sqlBuf bytes.Buffer
	var errFormat error
	for _, tokenParsed := range tokensParsed {
		errFormat = tokenParsed.Format(&sqlBuf, nil, 0)
		if errFormat != nil {
			break
		}
	}

	// Log formatting issue
	if errFormat != nil && !warned {
		warned = true
		logger.Warningf(
			"Could not format query: %s:\n%s",
			errFormat,
			"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
		)
		// Warn about issue, but continue
	}

	// Get formatted sql string
	sql = sqlBuf.String()

	// Compare if formatted query still has the same logic as input
	valid := sqlfmt.CompareSemantic(query, sql)
	if !valid && !warned {
		warned = true
		logger.Warningf(
			"Could not prettify query, output diverges:\n%s",
			"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
		)
		// Warn about issue, but continue
	}

	// Reset formatted SQL string to original input if there was an error
	if !valid || errFormat != nil || errParse != nil || errTokenizer != nil {
		sql = query
	}

	// Remove empty lines
	sql = strings.ReplaceAll(sql, "\n\n", "\n") // Remove empty lines

	// Remove empty spaces and linebreaks
	sql = trimEmptySyntax(sql) // Remove leading and trailing spaces and linebreaks

	// Return with what was found as tables
	// Empty if neither tokenizer nor manual search could match
	return tables, sql
}

// parseRows extracts the number of affected rows from a response's command tag
func parseRows(logger scanUtils.Logger, tag []byte) int {
	queryTag := string(tag)
	if strings.ToUpper(queryTag) == "DISCARD ALL" {
		return 0
	}
	queryTagFragments := strings.SplitN(queryTag, " ", -1)
	queryRowsFragment := ""
	if len(queryTagFragments) == 1 {
		return 0
	} else if len(queryTagFragments) == 2 {
		queryRowsFragment = queryTagFragments[1]
	} else if len(queryTagFragments) == 3 {
		queryRowsFragment = queryTagFragments[2]
	} else {
		logger.Errorf("Unexpected command tag '%s'.", queryTag)
		return 0
	}
	rows, errRows := strconv.Atoi(queryRowsFragment)
	if errRows != nil {
		logger.Errorf("Unexpected command tag rows count '%s'.", queryTag)
		return 0
	}
	return rows
}

// findTableNames iterates over the elements to search for FROM token types indicating a table name subsequently
func findTableNames(tokens []lexer.Token) []string {
	var tables []string
	var found = false
	for _, token := range tokens {
		if token.Type == lexer.FROM { // Mark found to indicate next value is table name
			found = true
		} else if found && token.Type == lexer.IDENT {
			if !scanUtils.StrContained(token.Value, tables) {
				tables = append(tables, token.Value)
			}
			found = false // Reset after associated IDENT was found
		} else {
			found = false // Reset because subsequent one was not an IDENT
		}
	}
	return tables
}
