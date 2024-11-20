package pgproxy

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/lithammer/shortuuid/v4"
	"github.com/noneymous/go-sqlfmt/sqlfmt"
	"github.com/noneymous/go-sqlfmt/sqlfmt/formatters"
	"github.com/noneymous/go-sqlfmt/sqlfmt/lexer"
	"github.com/noneymous/go-sqlfmt/sqlfmt/parser"
	cmap "github.com/orcaman/concurrent-map/v2"
	scanUtils "github.com/siemens/GoScans/utils"
	"gorm.io/gorm/utils"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const intervalConnectionsLog = time.Second * 30

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
	Pid        uint32
	Sid        uint32
	Database   string
	User       string
	Client     string
	Connection net.Conn
}

// PgReverseProxy defines a Postgres reverse proxy listening on a certain port, accepting incoming client
// connections and redirecting them to configured database servers, based on SNIs indicated by the client.
type PgReverseProxy struct {
	logger             scanUtils.Logger // PgProxy internal logger. Can be any fulfilling the specified logger interface
	listener           net.Listener     // PgProxy net listener listening for incoming client connections to be proxied
	listenerPort       uint             // PgProxy port to listen on
	listenerForceSsl   bool             // PgProxy flag whether to force SSL or allow plaintext connections
	listenerDefaultSni bool             // PgProxy flag whether to enable first listener config as default or to demand suitable SNI for incoming SSL connections
	listenerTimeout    time.Duration    // Inactivity timeout for connected clients
	listenerConfigs    map[string]Sni   // List of SNI certificates and database configurations to redirect clients

	connectionMap cmap.ConcurrentMap[string, PgConn] // Map to lookup network connections by backend key data
	connectionCtr uint                               // Counter for currently active proxy connections

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
	listenerForceSsl bool, // Whether to reject plain text connections
	listenerDefaultSni bool, // Whether to reject SSL connections without SNI. Without SNI the first SNI configuration would be applied as the default.
	listenerTimeout time.Duration,
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
		listenerForceSsl:     listenerForceSsl,
		listenerDefaultSni:   listenerDefaultSni,
		listenerTimeout:      listenerTimeout,
		listenerConfigs:      make(map[string]Sni),
		ctx:                  ctx,
		ctxCancelFunc:        ctxCancel,
		connectionsLogTicker: time.NewTicker(intervalConnectionsLog),
		connectionMap:        cmap.New[PgConn](),
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
	if p.connectionCtr > 0 {
		p.logger.Debugf("PgProxy has %d active connections left.", p.connectionCtr)
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
			msg += fmt.Sprintf("\n          Fingerprint   : %s", hex.EncodeToString(certFingerprint[:]))
			msg += fmt.Sprintf("\n          Common Name   : %s", v.CertificateX509.Subject.CommonName)
			if subjAltNames != "" {
				msg += fmt.Sprintf("\n          Subj Alt Names: %s", subjAltNames)
			}
			if subjAltIps != "" {
				msg += fmt.Sprintf("\n          Subj Alt IPs  : %s", subjAltIps)
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
			if errors.As(errClient, &net.ErrClosed) {
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
		p.connectionCtr += 1

		// Handle client connection
		go func() {

			// Decrease counter afterward
			defer func() { p.connectionCtr -= 1 }()

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

	// Set deadline initial deadline for client to complete handshake
	errDeadline := client.SetDeadline(time.Now().Add(time.Second * 10))
	if errDeadline != nil {
		logger.Errorf("Setting client deadline failed: %s.", errDeadline)
	}

	// Log initial message
	logger.Infof("Client connected from '%s'", client.RemoteAddr())

	// Prepare memory to remember SNI sent by client
	sni := ""

	// Prepare TLS configuration for client connections. TLS config contains a custom function
	// to select an applicable certificate based on the SNI indicated by the client hello.
	tlsClient := &tls.Config{
		GetCertificate: func(t *tls.ClientHelloInfo) (*tls.Certificate, error) {

			// Store SNI sent by client
			sni = t.ServerName

			// Get listener config based on SNI
			listenerConfig, okListenerConfig := p.listenerConfigs[t.ServerName]
			if !okListenerConfig {
				if t.ServerName == "" {
					return nil, &ErrCertificate{Message: fmt.Sprintf("no default certificate for empty SNI")}
				} else {
					return nil, &ErrCertificate{Message: fmt.Sprintf("no certificate for SNI '%s'", t.ServerName)}
				}
			}

			// Return related certificate
			return &listenerConfig.Certificate, nil
		},
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
		logger.Debugf("Returning fatal error to client.")
		errSend := clientBackend.Send(errResp)
		if errSend != nil {
			logger.Errorf("Could not return fatal error to client: %s.", errSend)
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
			if p.listenerForceSsl && !isSsl {

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

			// Make sure entry is cleaned from map after database connection is terminated
			defer func() {
				p.connectionMap.Remove(k)
			}()

			// Prepare cancel data
			buf := make([]byte, 16)
			binary.BigEndian.PutUint32(buf[0:4], 16)
			binary.BigEndian.PutUint32(buf[4:8], 80877102)
			binary.BigEndian.PutUint32(buf[8:12], m.ProcessID)
			binary.BigEndian.PutUint32(buf[12:16], m.SecretKey)

			// Send cancel request on connection
			_, errWrite := pgConn.Connection.Write(buf)
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
			_, errRead := pgConn.Connection.Read(buf)
			if errRead != nil {
				var opError *net.OpError
				if errors.As(errWrite, &opError) {
					// Ignore operational errors
				} else if errRead != io.EOF {
					// Ignore read error
				} else {
					logger.Errorf("Cancel request failed: %s.", errRead)
					return // Abort in case of communication error
				}
			}

			// Log success and abort further communication
			logger.Infof("Cancel request successful.")
			return

		case *pgproto3.SSLRequest:

			// Reject SSL encryption request, if not desired
			if tlsClient == nil {

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
			clientTls := tls.Server(client, tlsClient)
			errClientTls := clientTls.Handshake()
			if errors.Is(errClientTls, io.EOF) || errors.Is(errClientTls, syscall.ECONNRESET) { // Connection closed by client
				_ = clientTls.Close()
				logger.Debugf("Client terminated connection.")
				return
			} else if errors.As(errClientTls, &errCertificate) {

				// Prepare error to return to the client
				clientErrMsg = &pgconn.PgError{
					Code:    "FATAL",
					Message: "SSL connection with valid SNI required",
				}

				// Log issue andn return
				_ = clientTls.Close()
				logger.Infof("Client startup failed during SSL handshake: %s.", errClientTls)
				return
			} else if errClientTls != nil {
				_ = clientTls.Close()
				logger.Errorf("Client startup failed: could not execute SSL handshake: %s.", errClientTls)
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
			logger.Infof("Client connection without SNI cannot be dispatched, there is no default database.")
			return
		} else {

			// Prepare error to return to the client
			clientErrMsg = &pgconn.PgError{
				Code:    "FATAL",
				Message: "SSL connection with SNI required",
			}

			// Log situation and return
			logger.Infof("Client connection without SSL/SNI cannot be dispatched, there is no default database.")
			return
		}
	}

	// Log target database derived from connection settings
	if !isSsl {
		logger.Debugf("Client connection without SSL dispatching to DEFAULT database.")
	} else if sni == "" {
		logger.Debugf("Client connection without SNI dispatching to DEFAULT database.")
	} else {
		logger.Debugf("Client connection dispatching to database '%s'.", sni)
	}

	// Log user requesting connection
	logger.Debugf("Client connection authenticating as '%s'.", startupRaw.Parameters["user"])

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
		logger.Errorf("Database startup failed: no database configuration for '%s'.", sni)
		return // Abort in case of communication error
	}

	// Log database selection
	logger.Debugf("Proxying to database '%s'.", listenerConfig.Database.Host)

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
		logger.Errorf("Database startup failed: could not connect to database '%s': %s.", address, errDatabase)
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
		if utils.Contains([]string{"allow", "prefer", "require"}, listenerConfig.Database.SslMode) {
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
	logger.Infof("Caching connection details.")

	// Cache key data and associated database connection if available
	k := shortuuid.New()[0:10] // Chose random value if no key data is available
	if keyData != nil {
		k = generateKey(keyData)
	}

	// Store connection under key
	p.connectionMap.Set(k, PgConn{
		Pid:        keyData.ProcessID, // Might be 0 if no key data is available
		Sid:        keyData.SecretKey, // Might be 0 if no key data is available
		Database:   startupRaw.Parameters["database"],
		User:       startupRaw.Parameters["user"],
		Client:     startupRaw.Parameters["application_name"],
		Connection: connDatabase,
	})

	// Make sure entry is cleaned from map after database connection is terminated
	defer func() {
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
	type QueryData struct {
		Raw       string
		Queries   []string
		Timestamp time.Time
	}
	chQueryData := make(chan *QueryData, 1)

	// Listen for client requests
	go func() {

		// Log termination
		defer func() { logger.Debugf("Client receiver terminated.") }()

		// Increase wait group and make sure to decrease on termination
		wg.Add(1)
		defer wg.Done()

		// Catch potential panics to gracefully log issue with stacktrace
		defer func() {

			// Log issue
			if r := recover(); r != nil {
				logger.Errorf(fmt.Sprintf("Panic: %s%s", r, scanUtils.StacktraceIndented("\t")))
			}

			// Trigger end of communication and return
			chDone <- struct{}{}
			return
		}()

		// Prepare query cache for extended query flow / prepared statement,
		// where previous queries might be referenced and reused
		queryCache := make(map[string]string)

		// Prepare synced flag indicating whether database response can be expected.
		// Sending query data gain before database is ready to would get the query data channel stuck.
		synced := false

		// Loop and listen
		for {

			// Receive from client
			r, errR := clientBackend.Receive()
			if errR != nil {

				// Log error with respective criticality
				if errors.Is(errR, io.ErrUnexpectedEOF) { // Connection closed by client
					logger.Debugf("Client terminated connection.")
				} else if errors.Is(errR, os.ErrDeadlineExceeded) { // Connection closed by PgProxy because client was inactive
					logger.Infof("Client connection terminated due to inactivity.")
				} else if errors.As(errR, &net.ErrClosed) { // Connection closed by PgProxy
					// Connection closed by PgProxy
				} else { // Unexpected error
					logger.Errorf("Proxying data from client failed: %s.", errR)
				}

				// Indicate end of communication and return
				chDone <- struct{}{}
				return
			}

			// Update deadline for client to show activity
			errDeadlineUpdate := client.SetDeadline(time.Now().Add(p.listenerTimeout))
			if errDeadlineUpdate != nil {
				logger.Errorf("Updating client deadline failed: %s.", errDeadlineUpdate)
			}

			// Forwarding query data to database receiver routine
			if p.fnMonitoring != nil {
				logger.Debugf("Request  Type '%T'.", r)

				// Prepare data
				switch q := r.(type) {
				case *pgproto3.Query:
					query := strings.Trim(q.String, " ")
					chQueryData <- &QueryData{
						Raw:       query,               // Original query string. Might be single query or sequence of queries.
						Queries:   splitQueries(query), // Sequence of single queries contained in original query string.
						Timestamp: time.Now(),
					}
				case *pgproto3.Parse:
					logger.Debugf("Request  Type '%T', sending query data.", r)
					query := strings.Trim(q.Query, " ")
					chQueryData <- &QueryData{
						Raw:       query,               // Original query string. Might be single query or sequence of queries.
						Queries:   splitQueries(query), // Sequence of single queries contained in original query string.
						Timestamp: time.Now(),
					}
					queryCache[q.Name] = query
					synced = false
				case *pgproto3.Bind: // New command with previous query
					if synced { // Bind right after Parse would send the same queryData again and get the channel stuck. Sync needs to be observed first
						logger.Debugf("Request  Type '%T', sending query data.", r)
						query, okQuery := queryCache[q.PreparedStatement]
						if okQuery {
							query = strings.Trim(query, " ")
							chQueryData <- &QueryData{
								Raw:       query,               // Original query string. Might be single query or sequence of queries.
								Queries:   splitQueries(query), // Sequence of single queries contained in original query string.
								Timestamp: time.Now(),
							}
						}
					}
					synced = false
				case *pgproto3.Sync:
					synced = true
				default:
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

				// Indicate end of communication and return
				chDone <- struct{}{}
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

		// Increase wait group and make sure to decrease on termination
		wg.Add(1)
		defer wg.Done()

		// Cache current query executed
		var queryData = &QueryData{ // QueryData containing the query string currently worked on between the client and the database
			Raw:       "",
			Queries:   []string{},
			Timestamp: time.Time{},
		}
		var queryTime = time.Time{} // Timestamp when the query finished executing (before transmission of results)
		var commands = 0            // Amount of SQL commands processed by the backend (A query may contain multiple SQL commands)
		var rows = 0                // Amount of rows returned by an SQL command

		// Catch potential panics to gracefully log issue with stacktrace
		defer func() {

			// Log issue
			if r := recover(); r != nil {
				if queryData != nil {
					q := queryData.Raw
					if commands < len(queryData.Queries) {
						q = queryData.Queries[commands]
					}
					logger.Errorf(fmt.Sprintf("Panic: %s%s\n\tQuery:\n%s", r, scanUtils.StacktraceIndented("\t"), q))
				} else {
					logger.Errorf(fmt.Sprintf("Panic: %s%s", r, scanUtils.StacktraceIndented("\t")))
				}
			}

			// Trigger end of communication and return
			chDone <- struct{}{}
			return
		}()

		// Loop and listen
		for {

			// Receive from database
			r, errR := databaseFrontend.Receive()
			if errR != nil {

				// Log error with respective criticality
				if errors.Is(errR, io.ErrUnexpectedEOF) { // Connection closed by database
					logger.Infof("Database terminated connection: %s.", errR)
				} else if errors.As(errR, &net.ErrClosed) { // Connection closed by PgProxy
					// Connection closed by PgProxy
				} else { // Unexpected error
					logger.Errorf("Proxying data from server failed: %s.", errR)

					// Notify client about issue with backend database
					notifyClient(&pgconn.PgError{
						Code:    "FATAL",
						Message: errR.Error(),
					})
				}

				// Indicate end of communication and return
				chDone <- struct{}{}
				return
			}

			// Execute command monitoring if activated
			if p.fnMonitoring != nil {

				// Get query data (FrontendMessage), as communication segment has started
				if queryData.Raw == "" && len(queryData.Queries) == 0 { // Don't get next query until query data is reset by ReadyForQuery
					select {
					case queryData = <-chQueryData:
					default: // Still working on the previous query
					}
				}

				// Act on response depending on type
				switch commandResp := r.(type) {
				case *pgproto3.ErrorResponse:

					// Check if amount of responses still matches expected amounts
					var query string
					if commands >= len(queryData.Queries) {

						// Log secondary error
						logger.Errorf(
							"Received %d responses, while only %d were expected.",
							commands+1,
							len(queryData.Queries),
						)

						// Get query, prettify and unify for logging
						_, query = prettify(logger, queryData.Raw)

					} else { // Process response if it is as expected

						// Get query, prettify and unify for logging
						_, query = prettify(logger, queryData.Queries[commands])
					}

					// Log response type
					logger.Infof(
						"Response Type '%T': %s\n%s",
						commandResp,
						commandResp.Message,
						"    "+strings.Join(strings.Split(query, "\n"), "\n    "),
					)

				case *pgproto3.EmptyQueryResponse: // Empty query string

					// Postgres returns EmptyQueryResponse if there was nothing to execute
					logger.Debugf("Response Type '%T'.", commandResp)

				case *pgproto3.RowDescription:

					// Postgres returns one RowDescription response per command result
					logger.Debugf("Response Type '%T'.", commandResp)
					queryTime = time.Now()

				case *pgproto3.DataRow:

					// Postgres returns one DataRow response per result ROW!
					// Don't log, because it would bloat the log file.
					rows++

				case *pgproto3.CommandComplete:

					// Make up for skipped DataRow response logs with aggregated DataRow log entry
					if rows > 0 {
						logger.Debugf("Response Type '%T' (%dx).", &pgproto3.DataRow{}, rows)
					}

					// Check if amount of responses still matches expected amounts
					if commands >= len(queryData.Queries) {

						// Get query, prettify and unify for logging
						_, query := prettify(logger, queryData.Raw)

						// Log error
						logger.Errorf(
							"Received %d responses, while only %d were expected in this multi query:\n%s",
							commands+1,
							len(queryData.Queries),
							query,
						)
					} else { // Process response if it is as expected

						// Log action
						logger.Infof("Response Type '%T', logging command.", commandResp)

						// Get query, prettify and unify for logging
						tables, query := prettify(logger, queryData.Queries[commands])

						// Extract row count
						queryRows := parseRows(logger, commandResp.CommandTag)

						// Log command execution
						tEnd := time.Now()
						tExec := tEnd
						if !queryTime.IsZero() {
							tExec = queryTime
						}
						errMonitoring := p.fnMonitoring(
							logger,
							startupRaw.Parameters["database"],
							startupRaw.Parameters["user"],
							tables,
							query,
							queryRows,
							queryData.Timestamp,
							tExec,
							tEnd,
							startupRaw.Parameters["application_name"],
						)
						if errMonitoring != nil {
							logger.Errorf("Could not monitor query: %s.", errMonitoring)
						}
					}

					// Reset command's response row counter
					rows = 0

					// Increment command counter
					commands++

					// Reset query time for new timing
					queryTime = time.Time{}

				case *pgproto3.ParameterStatus: //  Informs the frontend about the current (initial) setting of a backend parameter

					// Update connection name in cached active connections
					if commandResp.Name == "application_name" && commandResp.Value != "" {

						// Update application name
						startupRaw.Parameters["application_name"] = commandResp.Value

						// Update cached information
						p.connectionMap.Set(k, PgConn{
							Pid:        keyData.ProcessID,
							Sid:        keyData.SecretKey,
							Database:   startupRaw.Parameters["database"],
							User:       startupRaw.Parameters["user"],
							Client:     startupRaw.Parameters["application_name"],
							Connection: connDatabase,
						})
					}

					// Might be sent by the backend automatically AFTER CommandComplete (e.g. if notification of client after SET command is intended)
					logger.Debugf("Response Type '%T', backend set '%s' to '%s'.", commandResp, commandResp.Name, commandResp.Value)

				case *pgproto3.ReadyForQuery:

					// Reset query data (FrontendMessage), as communication segment has come to an end
					logger.Debugf("Response Type '%T', resetting query data.", commandResp)
					queryData = &QueryData{
						Raw:       "",
						Queries:   []string{},
						Timestamp: time.Time{},
					}
					commands = 0

				default:
					logger.Debugf("Response Type '%T'.", commandResp)
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

				// Indicate end of communication and return
				chDone <- struct{}{}
				return
			}

			// Update deadline for client to show activity
			errDeadlineUpdate := client.SetDeadline(time.Now().Add(p.listenerTimeout))
			if errDeadlineUpdate != nil {
				logger.Errorf("Updating client deadline failed: %s.", errDeadlineUpdate)
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

	// Wait for all goroutines
	wg.Wait()
}

// logConnections prints currently active connections utilizing the logger
func (p *PgReverseProxy) logConnections() {
	msg := "Active database connections:"
	if p.connectionMap.Count() > 0 {
		for _, v := range p.connectionMap.Items() {
			msg += fmt.Sprintf(
				"\n    Pid: %-5d | Sid: %-10d | Origin: %-17s\t| Db: %-10s | User: %-25s \t| Client: '%s'",
				v.Pid,
				v.Sid,
				v.Connection.RemoteAddr(),
				v.Database,
				v.User,
				v.Client,
			)
		}
		p.logger.Debugf(msg)
	} else {
		msg += fmt.Sprintf("\n\t-")
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

// splitQueries checks whether a query consists out of multiple single queries to be executed by the database
// and returns a slice of single queries.
func splitQueries(sql string) []string {

	// Split queries by unquoted semicolon
	quotedSingle := false
	quotedDouble := false
	queries := strings.FieldsFunc(sql, func(r rune) bool {
		if r == '"' && !quotedSingle {
			quotedDouble = !quotedDouble
		}
		if r == '\'' && !quotedDouble {
			quotedSingle = !quotedSingle
		}
		return !quotedSingle && !quotedDouble && r == ';'
	})

	// Filter empty
	queriesSanitized := make([]string, 0, len(queries))
	for _, query := range queries {
		query = strings.Trim(query, " ")
		query = strings.Trim(query, "\n")
		if strings.ReplaceAll(strings.ReplaceAll(query, "\n", ""), " ", "") != "" {
			queriesSanitized = append(queriesSanitized, query)
		}
	}

	// Return split queries
	return queriesSanitized
}

// prettify returns a formatted SQL query string and a list of database tables it is targeting. An SQL query
// does not necessarily need to target a table. Also, it might target multiple ones via subqueries.
func prettify(logger scanUtils.Logger, query string) (tables []string, sql string) {

	// Unify spacings in the query
	query = strings.ReplaceAll(query, "    ", "  ") // Replace quad spaces with double spaces
	query = strings.ReplaceAll(query, "\t", "  ")   // Replace tabulators with double spaces

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
	for strings.HasPrefix(sql, "\n") || strings.HasSuffix(sql, "\n") ||
		strings.HasPrefix(sql, " ") || strings.HasSuffix(sql, " ") {
		sql = strings.Trim(sql, "\n") // Remove leading and trailing linebreaks
		sql = strings.Trim(sql, " ")  // Remove leading and trailing spaces
	}

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
			if !utils.Contains(tables, token.Value) {
				tables = append(tables, token.Value)
			}
			found = false // Reset after associated IDENT was found
		} else {
			found = false // Reset because subsequent one was not an IDENT
		}
	}
	return tables
}
