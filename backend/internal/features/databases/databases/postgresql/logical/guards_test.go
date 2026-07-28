package postgresql_logical

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ValidateIsNotDatabasusInternalDatabase_WhenReachedOnTheLocalMachine_ReturnsError(t *testing.T) {
	testCases := []struct {
		name         string
		host         string
		databaseName string
	}{
		{name: "localhost", host: "localhost", databaseName: "databasus"},
		{name: "127.0.0.1", host: "127.0.0.1", databaseName: "databasus"},
		{name: "172.17.0.1 docker bridge", host: "172.17.0.1", databaseName: "databasus"},
		{name: "host.docker.internal", host: "host.docker.internal", databaseName: "databasus"},
		{name: "uppercase host and name", host: "LOCALHOST", databaseName: "DATABASUS"},
		{name: "mixed case host and name", host: "LocalHost", databaseName: "DataBasus"},
		{name: "::1 IPv6 loopback", host: "::1", databaseName: "databasus"},
		{name: ":: IPv6 all interfaces", host: "::", databaseName: "databasus"},
		{name: "0.0.0.0 all IPv4 interfaces", host: "0.0.0.0", databaseName: "databasus"},
		{name: "127.0.0.2 inside the loopback range", host: "127.0.0.2", databaseName: "databasus"},
		{name: "127.255.255.255 end of the loopback range", host: "127.255.255.255", databaseName: "databasus"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateIsNotDatabasusInternalDatabase(ConnectionDestination{
				Host:         testCase.host,
				DatabaseName: testCase.databaseName,
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "backing up Databasus internal database is not allowed")
			assert.Contains(t, err.Error(), "https://databasus.com/faq#backup-databasus")
		})
	}
}

func Test_ValidateIsNotDatabasusInternalDatabase_WhenHostOrNameDiffers_ReturnsNoError(t *testing.T) {
	testCases := []struct {
		name         string
		host         string
		databaseName string
	}{
		{name: "remote host with the databasus name", host: "192.168.1.100", databaseName: "databasus"},
		{name: "local machine with another name", host: "localhost", databaseName: "myapp"},
		{name: "remote host with another name", host: "db.example.com", databaseName: "production"},
		{name: "local machine with the postgres name", host: "localhost", databaseName: "postgres"},
		{name: "empty name", host: "localhost", databaseName: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateIsNotDatabasusInternalDatabase(ConnectionDestination{
				Host:         testCase.host,
				DatabaseName: testCase.databaseName,
			})

			assert.NoError(t, err)
		})
	}
}

func Test_ValidateIsNotDatabasusInternalDatabase_WhenReachedThroughRemoteBastion_ReturnsNoError(t *testing.T) {
	err := ValidateIsNotDatabasusInternalDatabase(ConnectionDestination{
		Host:          "localhost",
		SshTunnelHost: "bastion.example.com",
		DatabaseName:  "databasus",
	})

	assert.NoError(t, err)
}

func Test_ValidateIsNotDatabasusInternalDatabase_WhenReachedThroughLocalBastion_ReturnsError(t *testing.T) {
	err := ValidateIsNotDatabasusInternalDatabase(ConnectionDestination{
		Host:          "127.0.0.1",
		SshTunnelHost: "127.0.0.1",
		DatabaseName:  "databasus",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "backing up Databasus internal database is not allowed")
}
