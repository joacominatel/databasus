package ssh_tunnel

import (
	"fmt"

	"github.com/google/uuid"

	"databasus-backend/internal/util/encryption"
)

type Tunnel struct {
	ID         uuid.UUID `json:"id"         gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	DatabaseID uuid.UUID `json:"databaseId" gorm:"column:database_id;type:uuid;not null"`

	Host     string `json:"host"     gorm:"column:host;type:text;not null"`
	Port     int    `json:"port"     gorm:"column:port;type:int;not null;default:22"`
	Username string `json:"username" gorm:"column:username;type:text;not null"`

	Password             string `json:"password"             gorm:"column:password;type:text;not null;default:''"`
	PrivateKey           string `json:"privateKey"           gorm:"column:private_key;type:text;not null;default:''"`
	PrivateKeyPassphrase string `json:"privateKeyPassphrase" gorm:"column:private_key_passphrase;type:text;not null;default:''"`

	HostKeyFingerprint     string `json:"hostKeyFingerprint"     gorm:"column:host_key_fingerprint;type:text;not null;default:''"`
	ShouldSkipHostKeyCheck bool   `json:"shouldSkipHostKeyCheck" gorm:"column:should_skip_host_key_check;type:bool;not null;default:false"`
}

func (t *Tunnel) TableName() string {
	return "database_ssh_tunnels"
}

func (t *Tunnel) Validate() error {
	if t.Host == "" {
		return ErrHostRequired
	}

	if t.Port <= 0 || t.Port > 65535 {
		return ErrPortOutOfRange
	}

	if t.Username == "" {
		return ErrUsernameRequired
	}

	if t.Password == "" && t.PrivateKey == "" {
		return ErrNoAuthMethod
	}

	if !t.ShouldSkipHostKeyCheck && t.HostKeyFingerprint == "" {
		return ErrHostKeyFingerprintMissing
	}

	return nil
}

func (t *Tunnel) Update(incoming *Tunnel) {
	t.Host = incoming.Host
	t.Port = incoming.Port
	t.Username = incoming.Username
	t.HostKeyFingerprint = incoming.HostKeyFingerprint
	t.ShouldSkipHostKeyCheck = incoming.ShouldSkipHostKeyCheck

	if incoming.Password != "" {
		t.Password = incoming.Password
	}

	if incoming.PrivateKey != "" {
		t.PrivateKey = incoming.PrivateKey
	}

	if incoming.PrivateKeyPassphrase != "" {
		t.PrivateKeyPassphrase = incoming.PrivateKeyPassphrase
	}
}

func (t *Tunnel) HideSensitiveData() {
	if t == nil {
		return
	}

	t.Password = ""
	t.PrivateKey = ""
	t.PrivateKeyPassphrase = ""
}

func (t *Tunnel) EncryptSensitiveFields(encryptor encryption.FieldEncryptor) error {
	for _, credential := range []*string{&t.Password, &t.PrivateKey, &t.PrivateKeyPassphrase} {
		if *credential == "" {
			continue
		}

		encrypted, err := encryptor.Encrypt(*credential)
		if err != nil {
			return fmt.Errorf("failed to encrypt SSH tunnel credentials: %w", err)
		}

		*credential = encrypted
	}

	return nil
}
