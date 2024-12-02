package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/noneymous/PgProxy/pgproxy"
	scanUtils "github.com/siemens/GoScans/utils"
	"log"
	"strings"
	"time"
)

// Example SNI configuration with a single SNI and target database
var snis = []pgproxy.Sni{
	{
		CertPath: "./keys/localhost_dev.crt", // Example self-signed certificate to be presented to the client
		KeyPath:  "./keys/localhost_dev.key", // Example self-signed certificate to be presented to the client
		Database: pgproxy.Database{
			Host:    "postgres.domain.tld", // The database host to proxy the client to
			Port:    5432,                  // The database port  to proxy the client to
			SslMode: "prefer",              // one out of pgproxy.SslModes
		},
		AllowedOrigins: nil, // Option to restrict access to SNI for a list of origin IPs
	},
}

func main() {

	// Initialize logger
	logger := new(Logger)

	// Print final message on exit
	defer func() {
		logger.Debugf("PgProxy terminated.")
	}()

	// Catch potential panics to log issue
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s", r))
		}
	}()

	// Prepare some reasonable TLS config
	tlsConf := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	}

	// Initialize PgProxy
	pgProxy, errPgProxy := pgproxy.Init(logger, 54321, tlsConf, false, true)
	if errPgProxy != nil {
		logger.Errorf("Could not initialize PgProxy: %s.", errPgProxy)
		return
	}

	// Register monitoring function (optional)
	pgProxy.RegisterMonitoring(func(
		loggerClient scanUtils.Logger, // Internal logger from PgProxy, within the context of a client connection
		dbName string,
		dbUser string,
		dbTables []string,
		query string,
		queryResults int,
		queryStart time.Time,
		queryEndExec time.Time,
		queryEndTotal time.Time,
		clientName string,
	) error {

		// Indent lines
		logMsg := "    " + strings.Join(strings.Split(query, "\n"), "\n    ")

		// Log query with stats
		logger.Debugf("Query of user '%s' ran %s and returned %d row(s) in %s: \n%s", dbUser, queryEndExec.Sub(queryStart), queryResults, queryEndTotal.Sub(queryStart), logMsg)

		// Return from monitoring function
		return nil
	})

	// Make sure core gets shut down gracefully
	defer pgProxy.Stop()

	// Load certificates from paths into memory
	for i, sni := range snis {
		jsn, _ := json.Marshal(sni)
		_ = snis[i].UnmarshalJSON(jsn)
	}

	// Register proxy interfaces and routes
	errAdd := pgProxy.RegisterSni(snis...)
	if errAdd != nil {
		logger.Errorf("Could not add PgProxy SNI: %s.", errAdd)
		return
	}

	// Listen and serve connections
	logger.Debugf("PgProxy running.")
	pgProxy.Serve()
}

// Logger is a wrapper around Golang's log module fulfilling interface required by PgProxy
type Logger struct {
}

func (l Logger) Debugf(format string, v ...interface{}) {
	log.Printf("DEBUG\t"+format, v...)
}
func (l Logger) Infof(format string, v ...interface{}) {
	log.Printf("INFO\t"+format, v...)
}
func (l Logger) Warningf(format string, v ...interface{}) {
	log.Printf("WARN\t"+format, v...)
}
func (l Logger) Errorf(format string, v ...interface{}) {
	log.Printf("ERROR\t"+format, v...)
}
