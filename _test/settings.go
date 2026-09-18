package _test

import "sync"

// PostgresBinDir must be set to enable integration tests, either here or with go test -ldflags -X
var PostgresBinDir string

var settings Settings      // Shared external test configuration
var settingsOnce sync.Once // Initializes settings once per test process

// Settings contains the external tools needed by the integration tests
type Settings struct {
	PostgresBinDir string // Directory containing initdb and pg_ctl; empty skips integration tests
}

// GetSettings returns the external test configuration
func GetSettings() *Settings {
	settingsOnce.Do(func() {
		settings.PostgresBinDir = PostgresBinDir
	})
	return &settings
}
