package usecases_logical_postgresql_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	backups_core_enums "databasus-backend/internal/features/backups/backups/core/enums"
	backups_core_logical "databasus-backend/internal/features/backups/backups/core/logical"
	usecases_logical_postgresql "databasus-backend/internal/features/backups/backups/usecases/logical/postgresql"
	backups_config_logical "databasus-backend/internal/features/backups/config/logical"
	"databasus-backend/internal/features/databases"
	postgresql_logical "databasus-backend/internal/features/databases/databases/postgresql/logical"
	"databasus-backend/internal/features/databases/ssh_tunnel"
	ssh_tunnel_testing "databasus-backend/internal/features/databases/ssh_tunnel/testing"
	"databasus-backend/internal/features/storages"
	local_storage "databasus-backend/internal/features/storages/models/local"
	"databasus-backend/internal/util/encryption"
	"databasus-backend/internal/util/testing/containers"
	"databasus-backend/internal/util/tools"
)

const (
	tunneledSourceImage     = "postgres:16"
	pgDumpCustomFormatMagic = "PGDMP"

	// The seeded volume has to dwarf the short metadata probes the Go drivers run over the same
	// tunnel, otherwise the relayed-byte comparison below could be met without pg_dump traffic.
	tunneledSourceRowCount       = 4000
	tunneledSourcePayloadRepeats = 32
)

// pg_dump only ever learns the tunnel's local endpoint, so a complete archive proves the whole
// dump crossed the SSH channel — the case Go drivers cannot cover, since pg_dump is an external
// binary with no knowledge of SSH.
func Test_CreateBackup_ThroughSshTunnel_BackupCompletes(t *testing.T) {
	sourceEndpoint := containers.StartPostgres(t, tunneledSourceImage)
	seedTunneledSource(t, sourceEndpoint)

	bastion := ssh_tunnel_testing.StartBastion(t, nil)
	tunneledDatabase := buildTunneledDatabase(t, sourceEndpoint, bastion)

	backup := &backups_core_logical.LogicalBackup{
		ID:         uuid.New(),
		DatabaseID: tunneledDatabase.ID,
		Status:     backups_core_logical.BackupStatusInProgress,
	}
	backup.GenerateFilename(tunneledDatabase.Name)

	storage := &storages.Storage{
		ID:           uuid.New(),
		Type:         storages.StorageTypeLocal,
		Name:         "tunneled backup storage",
		LocalStorage: &local_storage.LocalStorage{},
	}
	t.Cleanup(func() {
		_ = storage.DeleteFile(encryption.GetFieldEncryptor(), backup.FileName)
	})

	backupConfig := &backups_config_logical.LogicalBackupConfig{
		DatabaseID: tunneledDatabase.ID,
		Encryption: backups_core_enums.BackupEncryptionNone,
	}

	backupMetadata, err := usecases_logical_postgresql.GetCreatePostgresqlBackupUsecase().Execute(
		t.Context(),
		backup,
		backupConfig,
		tunneledDatabase,
		storage,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, backupMetadata)
	assert.Equal(t, backup.ID, backupMetadata.BackupID)
	assert.Equal(t, backups_core_enums.BackupEncryptionNone, backupMetadata.Encryption)

	archive := readStoredArchive(t, storage, backup.FileName)
	require.NotEmpty(t, archive)
	assert.True(
		t,
		bytes.HasPrefix(archive, []byte(pgDumpCustomFormatMagic)),
		"the stored file must be a pg_dump custom-format archive",
	)

	assert.Greater(
		t,
		bastion.GetBytesRelayedFromRemote(),
		int64(len(archive)),
		"the bastion must have relayed the whole dump stream, not just the metadata probes",
	)
}

func seedTunneledSource(t *testing.T, endpoint containers.Endpoint) {
	t.Helper()

	sourceDb, err := sqlx.Connect("postgres", fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		endpoint.Host,
		endpoint.Port,
		containers.PostgresUsername,
		containers.PostgresPassword,
		containers.PostgresDatabase,
	))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sourceDb.Close() })

	_, err = sourceDb.Exec(fmt.Sprintf(`
		CREATE TABLE tunneled_backup_rows (
		    id      SERIAL PRIMARY KEY,
		    payload TEXT NOT NULL
		);

		INSERT INTO tunneled_backup_rows (payload)
		SELECT repeat(md5(random()::text), %d)
		FROM generate_series(1, %d);
	`, tunneledSourcePayloadRepeats, tunneledSourceRowCount))
	require.NoError(t, err)
}

// The engine endpoint is the address seen from the bastion, so the container endpoint stays on the
// engine model and only the tunnel is reachable from this process' point of view.
func buildTunneledDatabase(
	t *testing.T,
	endpoint containers.Endpoint,
	bastion *ssh_tunnel_testing.Bastion,
) *databases.Database {
	t.Helper()

	encryptor := encryption.GetFieldEncryptor()

	databasePassword, err := encryptor.Encrypt(containers.PostgresPassword)
	require.NoError(t, err)

	bastionPassword, err := encryptor.Encrypt(ssh_tunnel_testing.BastionPassword)
	require.NoError(t, err)

	sourceDatabaseName := containers.PostgresDatabase

	tunneledDatabase := &databases.Database{
		ID:   uuid.New(),
		Name: "tunneled backup source",
		Type: databases.DatabaseTypePostgresLogical,
		PostgresqlLogical: &postgresql_logical.PostgresqlLogicalDatabase{
			Version:  tools.PostgresqlVersion16,
			Host:     endpoint.Host,
			Port:     endpoint.Port,
			Username: containers.PostgresUsername,
			Password: databasePassword,
			Database: &sourceDatabaseName,
			CpuCount: 1,
		},
		SshTunnel: &ssh_tunnel.Tunnel{
			Host:               bastion.GetHost(),
			Port:               bastion.GetPort(),
			Username:           ssh_tunnel_testing.BastionUsername,
			Password:           bastionPassword,
			HostKeyFingerprint: bastion.GetHostKeyFingerprint(),
		},
	}

	require.NoError(t, tunneledDatabase.Validate())

	return tunneledDatabase
}

func readStoredArchive(t *testing.T, storage *storages.Storage, fileName string) []byte {
	t.Helper()

	storedFile, err := storage.GetFile(encryption.GetFieldEncryptor(), fileName)
	require.NoError(t, err)
	defer func() { _ = storedFile.Close() }()

	archive, err := io.ReadAll(storedFile)
	require.NoError(t, err)

	return archive
}
