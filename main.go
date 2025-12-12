package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/noneymous/PgProxy/pgproxy"
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

	// Define client timeout duration
	clientTimeout := time.Second * 60 * 10

	// Initialize PgProxy
	pgProxy, errPgProxy := pgproxy.Init(logger, 54321, false, true, clientTimeout)
	if errPgProxy != nil {
		logger.Errorf("Could not initialize PgProxy: %s.", errPgProxy)
		return
	}

	// Log client timeout
	logger.Infof("Client timeout set to %s.", clientTimeout.String())

	// Register monitoring function (optional)
	pgProxy.RegisterMonitoring(func(
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
		errUnmarshal := snis[i].UnmarshalJSON(jsn)
		if errUnmarshal != nil {
			logger.Errorf("Could not load SNI certificate: %s.", errUnmarshal)
			return
		}
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
