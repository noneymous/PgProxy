package pgproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	scanUtils "github.com/siemens/GoScans/utils"
	"os"
	"strings"
)

// SslModes defines valid settings for establishing encrypted database connections
var SslModes = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}

type Sni struct {
	CertPath       string   `json:"cert_path"`       // SSL certificate presented to the database client
	KeyPath        string   `json:"key_path"`        // SSL certificate presented to the database client
	Database       Database `json:"database"`        // Target database to redirect clients to
	AllowedOrigins []string `json:"allowed_origins"` // Whitelist of IPs allowed to access this SNI

	Certificate     tls.Certificate  `json:"-"` // To  be loaded from cert and key path and not Json serializable
	CertificateX509 x509.Certificate `json:"-"` // To  be loaded from cert and key path and not Json serializable
}

func (d *Sni) UnmarshalJSON(b []byte) error {

	// Prepare temporary auxiliary data structure to load raw Json data
	type aux Sni
	var raw aux

	// Unmarshal serialized Json into temporary auxiliary structure
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	// Check values
	if _, errFile := os.ReadFile(raw.CertPath); errFile != nil {
		return fmt.Errorf("invalid certificate: %s", errFile)
	}
	if _, errFile := os.ReadFile(raw.KeyPath); errFile != nil {
		return fmt.Errorf("invalid key: %s", errFile)
	}

	// Update struct with de-serialized values
	*d = Sni(raw)

	// Load certificate from paths to verify
	cer, errCert := tls.LoadX509KeyPair(raw.CertPath, raw.KeyPath)
	if errCert != nil {
		return errCert
	}

	// Read and parse the certificate content
	cert, errParse := x509.ParseCertificate(cer.Certificate[0])
	if errParse != nil {
		return fmt.Errorf("could not parse certificate: %s", errParse)
	}

	// Set loaded certificates
	d.Certificate = cer       // Certificate bytes used by the TLS config/listener
	d.CertificateX509 = *cert // Parsed x509 certificate with all the certificate details

	// Return nil as everything went fine
	return nil
}

type Database struct {
	Host    string `json:"host"`     // Database host the client is proxied to
	Port    uint16 `json:"port"`     // Database port the client is proxied to
	SslMode string `json:"ssl_mode"` // One of Postgres' SSL mode values (disable, allow, prefer, require, verify-ca, verify-full)
}

func (t *Database) UnmarshalJSON(b []byte) error {

	// Prepare temporary auxiliary data structure to load raw Json data
	type aux Database
	var raw aux

	// Unmarshal serialized Json into temporary auxiliary structure
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	// Check values
	if raw.Port < 0 || raw.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if len(raw.Host) <= 4 {
		return fmt.Errorf("invalid host")
	}
	if !scanUtils.StrContained(raw.SslMode, SslModes) {
		return fmt.Errorf("valid ssl modes are: %s", strings.Join(SslModes, ", "))
	}

	// Update struct with de-serialized values
	*t = Database(raw)

	// Return nil as everything went fine
	return nil
}
