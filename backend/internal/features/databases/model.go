package databases

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"databasus-backend/internal/features/databases/databases/mariadb"
	"databasus-backend/internal/features/databases/databases/mongodb"
	"databasus-backend/internal/features/databases/databases/mysql"
	postgresql_logical "databasus-backend/internal/features/databases/databases/postgresql/logical"
	postgresql_physical "databasus-backend/internal/features/databases/databases/postgresql/physical"
	"databasus-backend/internal/features/databases/ssh_tunnel"
	"databasus-backend/internal/features/notifiers"
	"databasus-backend/internal/util/encryption"
)

type Database struct {
	ID uuid.UUID `json:"id" gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`

	// WorkspaceID can be null when a database is created via restore operation
	// outside the context of any workspace
	WorkspaceID *uuid.UUID   `json:"workspaceId" gorm:"column:workspace_id;type:uuid"`
	Name        string       `json:"name"        gorm:"column:name;type:text;not null"`
	Type        DatabaseType `json:"type"        gorm:"column:type;type:text;not null"`

	PostgresqlLogical  *postgresql_logical.PostgresqlLogicalDatabase   `json:"postgresqlLogical,omitzero"  gorm:"foreignKey:DatabaseID"`
	PostgresqlPhysical *postgresql_physical.PostgresqlPhysicalDatabase `json:"postgresqlPhysical,omitzero" gorm:"foreignKey:DatabaseID"`
	Mysql              *mysql.MysqlDatabase                            `json:"mysql,omitzero"              gorm:"foreignKey:DatabaseID"`
	Mariadb            *mariadb.MariadbDatabase                        `json:"mariadb,omitzero"            gorm:"foreignKey:DatabaseID"`
	Mongodb            *mongodb.MongodbDatabase                        `json:"mongodb,omitzero"            gorm:"foreignKey:DatabaseID"`

	SshTunnel *ssh_tunnel.Tunnel `json:"sshTunnel,omitzero" gorm:"foreignKey:DatabaseID"`

	Notifiers []notifiers.Notifier `json:"notifiers" gorm:"many2many:database_notifiers;"`

	// these fields are not reliable, but
	// they are used for pretty UI
	LastBackupTime         *time.Time `json:"lastBackupTime,omitzero"          gorm:"column:last_backup_time;type:timestamp with time zone"`
	LastBackupErrorMessage *string    `json:"lastBackupErrorMessage,omitempty" gorm:"column:last_backup_error_message;type:text"`

	HealthStatus *HealthStatus `json:"healthStatus" gorm:"column:health_status;type:text;not null"`
}

func (d *Database) Validate() error {
	if d.Name == "" {
		return errors.New("name is required")
	}

	sshTunnelHost := ""

	if d.SshTunnel != nil {
		if d.Type == DatabaseTypePostgresPhysical {
			return errors.New("ssh tunnel is not supported for physical postgresql databases yet")
		}

		if err := d.SshTunnel.Validate(); err != nil {
			return err
		}

		sshTunnelHost = d.SshTunnel.Host
	}

	switch d.Type {
	case DatabaseTypePostgresLogical:
		if d.PostgresqlLogical == nil {
			return errors.New("postgresql database is required")
		}

		if err := d.PostgresqlLogical.Validate(); err != nil {
			return err
		}

		return postgresql_logical.ValidateIsNotDatabasusInternalDatabase(
			postgresql_logical.ConnectionDestination{
				Host:          d.PostgresqlLogical.Host,
				SshTunnelHost: sshTunnelHost,
				DatabaseName:  d.PostgresqlLogical.GetDatabaseName(),
			},
		)
	case DatabaseTypePostgresPhysical:
		if d.PostgresqlPhysical == nil {
			return errors.New("postgresql physical database is required")
		}
		return d.PostgresqlPhysical.Validate()
	case DatabaseTypeMysql:
		if d.Mysql == nil {
			return errors.New("mysql database is required")
		}
		return d.Mysql.Validate()
	case DatabaseTypeMariadb:
		if d.Mariadb == nil {
			return errors.New("mariadb database is required")
		}
		return d.Mariadb.Validate()
	case DatabaseTypeMongodb:
		if d.Mongodb == nil {
			return errors.New("mongodb database is required")
		}
		return d.Mongodb.Validate()
	default:
		return errors.New("invalid database type: " + string(d.Type))
	}
}

func (d *Database) ValidateUpdate(old, new Database) error {
	// Database type cannot be changed after creation — the entire backup
	// structure (storage files, schedulers, etc.) is tied to the type at
	// creation time. Recreating that state automatically is error-prone;
	// it is safer for the user to create a new database and remove the old.
	if old.Type != new.Type {
		return errors.New("database type cannot be changed; create a new database instead")
	}

	if old.Type == DatabaseTypePostgresLogical && old.PostgresqlLogical != nil && new.PostgresqlLogical != nil {
		if err := new.PostgresqlLogical.ValidateUpdate(old.PostgresqlLogical); err != nil {
			return err
		}
	}

	if old.Type == DatabaseTypePostgresPhysical &&
		old.PostgresqlPhysical != nil && new.PostgresqlPhysical != nil {
		if err := new.PostgresqlPhysical.ValidateUpdate(old.PostgresqlPhysical); err != nil {
			return err
		}
	}

	return nil
}

type engineEndpoint struct {
	Host string
	Port int
}

// The returned database is a copy whenever a tunnel is opened: concurrent backups share one
// Database, so rewriting the engine endpoint in place would be a data race.
func (d *Database) OpenReachableDatabase(
	ctx context.Context,
	logger *slog.Logger,
	encryptor encryption.FieldEncryptor,
) (*Database, *ssh_tunnel.OpenedTunnel, error) {
	if d.SshTunnel == nil {
		return d, nil, nil
	}

	destination, err := d.getEngineEndpoint()
	if err != nil {
		return nil, nil, err
	}

	openedTunnel, err := d.SshTunnel.Open(ctx, ssh_tunnel.ForwardSpec{
		Logger:     logger.With("database_id", d.ID),
		Encryptor:  encryptor,
		RemoteHost: destination.Host,
		RemotePort: destination.Port,
	})
	if err != nil {
		return nil, nil, err
	}

	localHost, localPort := openedTunnel.GetLocalEndpoint()

	reachableDatabase := d.cloneWithEngineEndpoint(engineEndpoint{
		Host: localHost,
		Port: localPort,
	})

	return reachableDatabase, openedTunnel, nil
}

func closeTunnel(logger *slog.Logger, openedTunnel *ssh_tunnel.OpenedTunnel) {
	if openedTunnel == nil {
		return
	}

	if err := openedTunnel.Close(); err != nil {
		logger.Error("failed to close ssh tunnel", "error", err)
	}
}

func (d *Database) TestConnection(
	logger *slog.Logger,
	encryptor encryption.FieldEncryptor,
) error {
	reachableDatabase, openedTunnel, err := d.OpenReachableDatabase(
		context.Background(),
		logger,
		encryptor,
	)
	if err != nil {
		return err
	}
	defer closeTunnel(logger, openedTunnel)
	defer d.copyDetectedEngineData(reachableDatabase)

	switch reachableDatabase.Type {
	case DatabaseTypePostgresLogical:
		if reachableDatabase.PostgresqlLogical == nil {
			return errors.New("postgresql logical config is not set")
		}

		return reachableDatabase.PostgresqlLogical.TestConnection(logger, encryptor)
	case DatabaseTypePostgresPhysical:
		if reachableDatabase.PostgresqlPhysical == nil {
			return errors.New("postgresql physical config is not set")
		}

		return reachableDatabase.PostgresqlPhysical.TestReplicationConnection(logger, encryptor)
	case DatabaseTypeMysql:
		if reachableDatabase.Mysql == nil {
			return errors.New("mysql config is not set")
		}

		return reachableDatabase.Mysql.TestConnection(logger, encryptor)
	case DatabaseTypeMariadb:
		if reachableDatabase.Mariadb == nil {
			return errors.New("mariadb config is not set")
		}

		return reachableDatabase.Mariadb.TestConnection(logger, encryptor)
	case DatabaseTypeMongodb:
		if reachableDatabase.Mongodb == nil {
			return errors.New("mongodb config is not set")
		}

		return reachableDatabase.Mongodb.TestConnection(logger, encryptor)
	default:
		return errors.New("connection test not supported for database type: " + string(d.Type))
	}
}

func (d *Database) GetRawDbSizeMb(
	ctx context.Context,
	logger *slog.Logger,
	encryptor encryption.FieldEncryptor,
) (float64, error) {
	reachableDatabase, openedTunnel, err := d.OpenReachableDatabase(ctx, logger, encryptor)
	if err != nil {
		return 0, err
	}
	defer closeTunnel(logger, openedTunnel)

	switch reachableDatabase.Type {
	case DatabaseTypePostgresLogical:
		if reachableDatabase.PostgresqlLogical == nil {
			return 0, errors.New("postgresql logical config is not set")
		}

		return reachableDatabase.PostgresqlLogical.GetRawDbSizeMb(ctx, logger, encryptor)
	case DatabaseTypeMysql:
		if reachableDatabase.Mysql == nil {
			return 0, errors.New("mysql config is not set")
		}

		return reachableDatabase.Mysql.GetRawDbSizeMb(ctx, logger, encryptor)
	case DatabaseTypeMariadb:
		if reachableDatabase.Mariadb == nil {
			return 0, errors.New("mariadb config is not set")
		}

		return reachableDatabase.Mariadb.GetRawDbSizeMb(ctx, logger, encryptor)
	case DatabaseTypeMongodb:
		if reachableDatabase.Mongodb == nil {
			return 0, errors.New("mongodb config is not set")
		}

		return reachableDatabase.Mongodb.GetRawDbSizeMb(ctx, logger, encryptor)
	default:
		return 0, errors.New("logical backup not supported for database type: " + string(d.Type))
	}
}

func (d *Database) IsUserReadOnly(
	ctx context.Context,
	logger *slog.Logger,
	encryptor encryption.FieldEncryptor,
) (bool, []string, error) {
	reachableDatabase, openedTunnel, err := d.OpenReachableDatabase(ctx, logger, encryptor)
	if err != nil {
		return false, nil, err
	}
	defer closeTunnel(logger, openedTunnel)

	switch reachableDatabase.Type {
	case DatabaseTypePostgresLogical:
		return reachableDatabase.PostgresqlLogical.IsUserReadOnly(ctx, logger, encryptor)
	case DatabaseTypePostgresPhysical:
		return reachableDatabase.PostgresqlPhysical.IsUserReplicationOnly(ctx, logger, encryptor)
	case DatabaseTypeMysql:
		return reachableDatabase.Mysql.IsUserReadOnly(ctx, logger, encryptor)
	case DatabaseTypeMariadb:
		return reachableDatabase.Mariadb.IsUserReadOnly(ctx, logger, encryptor)
	case DatabaseTypeMongodb:
		return reachableDatabase.Mongodb.IsUserReadOnly(ctx, logger, encryptor)
	default:
		return false, nil, errors.New("read-only check not supported for this database type")
	}
}

func (d *Database) HideSensitiveData() {
	if d.PostgresqlLogical != nil {
		d.PostgresqlLogical.HideSensitiveData()
	}
	if d.PostgresqlPhysical != nil {
		d.PostgresqlPhysical.HideSensitiveData()
	}
	if d.Mysql != nil {
		d.Mysql.HideSensitiveData()
	}
	if d.Mariadb != nil {
		d.Mariadb.HideSensitiveData()
	}
	if d.Mongodb != nil {
		d.Mongodb.HideSensitiveData()
	}
	if d.SshTunnel != nil {
		d.SshTunnel.HideSensitiveData()
	}
}

// The tunnel coexists with any engine, so it is encrypted on top of the engine and not instead
// of it.
func (d *Database) EncryptSensitiveFields(encryptor encryption.FieldEncryptor) error {
	if d.SshTunnel != nil {
		if err := d.SshTunnel.EncryptSensitiveFields(encryptor); err != nil {
			return err
		}
	}

	if d.PostgresqlLogical != nil {
		return d.PostgresqlLogical.EncryptSensitiveFields(encryptor)
	}
	if d.PostgresqlPhysical != nil {
		return d.PostgresqlPhysical.EncryptSensitiveFields(encryptor)
	}
	if d.Mysql != nil {
		return d.Mysql.EncryptSensitiveFields(encryptor)
	}
	if d.Mariadb != nil {
		return d.Mariadb.EncryptSensitiveFields(encryptor)
	}
	if d.Mongodb != nil {
		return d.Mongodb.EncryptSensitiveFields(encryptor)
	}
	return nil
}

func (d *Database) PopulateDbData(
	logger *slog.Logger,
	encryptor encryption.FieldEncryptor,
) error {
	reachableDatabase, openedTunnel, err := d.OpenReachableDatabase(
		context.Background(),
		logger,
		encryptor,
	)
	if err != nil {
		return err
	}
	defer closeTunnel(logger, openedTunnel)
	defer d.copyDetectedEngineData(reachableDatabase)

	if reachableDatabase.PostgresqlLogical != nil {
		return reachableDatabase.PostgresqlLogical.PopulateDbData(logger, encryptor)
	}
	if reachableDatabase.PostgresqlPhysical != nil {
		return reachableDatabase.PostgresqlPhysical.PopulateDbData(logger, encryptor)
	}
	if reachableDatabase.Mysql != nil {
		return reachableDatabase.Mysql.PopulateDbData(logger, encryptor)
	}
	if reachableDatabase.Mariadb != nil {
		return reachableDatabase.Mariadb.PopulateDbData(logger, encryptor)
	}
	if reachableDatabase.Mongodb != nil {
		return reachableDatabase.Mongodb.PopulateDbData(logger, encryptor)
	}
	return nil
}

func (d *Database) Update(incoming *Database) {
	d.Name = incoming.Name
	d.Type = incoming.Type
	d.Notifiers = incoming.Notifiers

	switch d.Type {
	case DatabaseTypePostgresLogical:
		if d.PostgresqlLogical != nil && incoming.PostgresqlLogical != nil {
			d.PostgresqlLogical.Update(incoming.PostgresqlLogical)
		}
	case DatabaseTypePostgresPhysical:
		if d.PostgresqlPhysical != nil && incoming.PostgresqlPhysical != nil {
			d.PostgresqlPhysical.Update(incoming.PostgresqlPhysical)
		}
	case DatabaseTypeMysql:
		if d.Mysql != nil && incoming.Mysql != nil {
			d.Mysql.Update(incoming.Mysql)
		}
	case DatabaseTypeMariadb:
		if d.Mariadb != nil && incoming.Mariadb != nil {
			d.Mariadb.Update(incoming.Mariadb)
		}
	case DatabaseTypeMongodb:
		if d.Mongodb != nil && incoming.Mongodb != nil {
			d.Mongodb.Update(incoming.Mongodb)
		}
	}

	d.updateSshTunnel(incoming.SshTunnel)
}

func (d *Database) updateSshTunnel(incoming *ssh_tunnel.Tunnel) {
	if incoming == nil {
		d.SshTunnel = nil

		return
	}

	if d.SshTunnel == nil {
		incoming.ID = uuid.Nil
		incoming.DatabaseID = d.ID
		d.SshTunnel = incoming

		return
	}

	d.SshTunnel.Update(incoming)
}

// The endpoint stored on the engine model is the one seen from the bastion, so it is what the
// forward has to reach.
func (d *Database) getEngineEndpoint() (engineEndpoint, error) {
	switch d.Type {
	case DatabaseTypePostgresLogical:
		if d.PostgresqlLogical == nil {
			return engineEndpoint{}, errors.New("postgresql logical config is not set")
		}

		return engineEndpoint{Host: d.PostgresqlLogical.Host, Port: d.PostgresqlLogical.Port}, nil
	case DatabaseTypeMysql:
		if d.Mysql == nil {
			return engineEndpoint{}, errors.New("mysql config is not set")
		}

		return engineEndpoint{Host: d.Mysql.Host, Port: d.Mysql.Port}, nil
	case DatabaseTypeMariadb:
		if d.Mariadb == nil {
			return engineEndpoint{}, errors.New("mariadb config is not set")
		}

		return engineEndpoint{Host: d.Mariadb.Host, Port: d.Mariadb.Port}, nil
	case DatabaseTypeMongodb:
		if d.Mongodb == nil {
			return engineEndpoint{}, errors.New("mongodb config is not set")
		}

		if d.Mongodb.Port == nil || *d.Mongodb.Port == 0 {
			return engineEndpoint{}, errors.New(
				"ssh tunnel requires an explicit mongodb port, srv connections are not supported",
			)
		}

		return engineEndpoint{Host: d.Mongodb.Host, Port: *d.Mongodb.Port}, nil
	default:
		return engineEndpoint{}, errors.New(
			"ssh tunnel is not supported for database type: " + string(d.Type),
		)
	}
}

func (d *Database) cloneWithEngineEndpoint(endpoint engineEndpoint) *Database {
	reachableDatabase := *d

	switch d.Type {
	case DatabaseTypePostgresLogical:
		reachableEngine := *d.PostgresqlLogical
		reachableEngine.Host = endpoint.Host
		reachableEngine.Port = endpoint.Port

		reachableDatabase.PostgresqlLogical = &reachableEngine
	case DatabaseTypeMysql:
		reachableEngine := *d.Mysql
		reachableEngine.Host = endpoint.Host
		reachableEngine.Port = endpoint.Port

		reachableDatabase.Mysql = &reachableEngine
	case DatabaseTypeMariadb:
		reachableEngine := *d.Mariadb
		reachableEngine.Host = endpoint.Host
		reachableEngine.Port = endpoint.Port

		reachableDatabase.Mariadb = &reachableEngine
	case DatabaseTypeMongodb:
		reachableEngine := *d.Mongodb
		reachableEngine.Host = endpoint.Host
		reachableEngine.Port = &endpoint.Port

		reachableDatabase.Mongodb = &reachableEngine
	}

	return &reachableDatabase
}

// Connection probes write what they detect (version, privileges) onto the engine model they ran
// against, which is the tunnel copy — the stored model would keep an empty version otherwise.
func (d *Database) copyDetectedEngineData(probedDatabase *Database) {
	if probedDatabase == d {
		return
	}

	switch d.Type {
	case DatabaseTypePostgresLogical:
		d.PostgresqlLogical.Version = probedDatabase.PostgresqlLogical.Version
	case DatabaseTypeMysql:
		d.Mysql.Version = probedDatabase.Mysql.Version
		d.Mysql.Privileges = probedDatabase.Mysql.Privileges
	case DatabaseTypeMariadb:
		d.Mariadb.Version = probedDatabase.Mariadb.Version
		d.Mariadb.Privileges = probedDatabase.Mariadb.Privileges
	case DatabaseTypeMongodb:
		d.Mongodb.Version = probedDatabase.Mongodb.Version
	}
}
