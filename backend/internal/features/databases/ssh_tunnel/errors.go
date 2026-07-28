package ssh_tunnel

import "errors"

var (
	ErrHostRequired              = errors.New("SSH tunnel host is required")
	ErrPortOutOfRange            = errors.New("SSH tunnel port must be between 1 and 65535")
	ErrUsernameRequired          = errors.New("SSH tunnel username is required")
	ErrNoAuthMethod              = errors.New("SSH tunnel password or private key is required")
	ErrHostKeyFingerprintMissing = errors.New(
		"SSH tunnel host key fingerprint is required unless the host key check is explicitly skipped",
	)
	ErrHostKeyMismatch = errors.New("SSH tunnel host key does not match the configured fingerprint")
)
