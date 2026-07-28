package postgresql_logical

import (
	"errors"
	"slices"
	"strings"
)

const databasusInternalDatabaseName = "databasus"

var localMachineAddresses = []string{
	"localhost",
	"127.0.0.1",
	"172.17.0.1",
	"host.docker.internal",
	"::1",
	"::",
	"0.0.0.0",
}

type ConnectionDestination struct {
	Host          string
	SshTunnelHost string
	DatabaseName  string
}

// Databasus runs an internal PostgreSQL instance that must not be backed up through the UI:
// it would expose internal metadata to non-system administrators.
// To back up Databasus itself, see https://databasus.com/faq#backup-databasus
func ValidateIsNotDatabasusInternalDatabase(destination ConnectionDestination) error {
	if !strings.EqualFold(destination.DatabaseName, databasusInternalDatabaseName) {
		return nil
	}

	if !isLocalMachineAddress(destination.Host) {
		return nil
	}

	// Seen from a bastion, a loopback host is that bastion's own PostgreSQL — only a bastion
	// running on the Databasus machine can forward to the internal database.
	if destination.SshTunnelHost != "" && !isLocalMachineAddress(destination.SshTunnelHost) {
		return nil
	}

	return errors.New(
		"backing up Databasus internal database is not allowed. To backup Databasus itself, see https://databasus.com/faq#backup-databasus",
	)
}

func isLocalMachineAddress(host string) bool {
	if strings.HasPrefix(host, "127.") {
		return true
	}

	return slices.ContainsFunc(localMachineAddresses, func(localAddress string) bool {
		return strings.EqualFold(host, localAddress)
	})
}
