package ssh_tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"databasus-backend/internal/util/encryption"
)

const (
	sshConnectTimeout = 30 * time.Second
	loopbackHost      = "127.0.0.1"
)

type ForwardSpec struct {
	Logger     *slog.Logger
	Encryptor  encryption.FieldEncryptor
	RemoteHost string
	RemotePort int
}

type OpenedTunnel struct {
	listener      net.Listener
	sshClient     *ssh.Client
	logger        *slog.Logger
	remoteAddress string
	localHost     string
	localPort     int

	forwardingCtx        context.Context
	stopForwarding       context.CancelFunc
	acceptLoop           sync.WaitGroup
	forwardedConnections sync.WaitGroup
	closeOnce            sync.Once
	closeErr             error
}

type writeHalfCloser interface {
	CloseWrite() error
}

func (t *Tunnel) Open(ctx context.Context, spec ForwardSpec) (*OpenedTunnel, error) {
	authMethods, err := t.buildAuthMethods(spec.Encryptor)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := t.buildHostKeyCallback()
	if err != nil {
		return nil, err
	}

	bastionAddress := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))

	dialer := net.Dialer{Timeout: sshConnectTimeout}

	bastionConn, err := dialer.DialContext(ctx, "tcp", bastionAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH tunnel host: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}

	sshConn, newChannels, requests, err := ssh.NewClientConn(bastionConn, bastionAddress, clientConfig)
	if err != nil {
		_ = bastionConn.Close()

		return nil, fmt.Errorf("failed to establish SSH tunnel connection: %w", err)
	}

	sshClient := ssh.NewClient(sshConn, newChannels, requests)

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(ctx, "tcp", net.JoinHostPort(loopbackHost, "0"))
	if err != nil {
		_ = sshClient.Close()

		return nil, fmt.Errorf("failed to listen for SSH tunnel forwarding: %w", err)
	}

	localAddress, isTcpAddress := listener.Addr().(*net.TCPAddr)
	if !isTcpAddress {
		_ = listener.Close()
		_ = sshClient.Close()

		return nil, fmt.Errorf("unexpected SSH tunnel listener address type %T", listener.Addr())
	}

	forwardingCtx, stopForwarding := context.WithCancel(ctx)

	openedTunnel := &OpenedTunnel{
		listener:       listener,
		sshClient:      sshClient,
		logger:         spec.Logger.With("ssh_tunnel_host", t.Host, "ssh_tunnel_port", t.Port),
		remoteAddress:  net.JoinHostPort(spec.RemoteHost, strconv.Itoa(spec.RemotePort)),
		localHost:      localAddress.IP.String(),
		localPort:      localAddress.Port,
		forwardingCtx:  forwardingCtx,
		stopForwarding: stopForwarding,
	}

	openedTunnel.acceptLoop.Go(openedTunnel.acceptConnections)

	openedTunnel.logger.Debug(fmt.Sprintf(
		"ssh tunnel opened, forwarding %s:%d to %s",
		openedTunnel.localHost,
		openedTunnel.localPort,
		openedTunnel.remoteAddress,
	))

	return openedTunnel, nil
}

func (t *Tunnel) buildAuthMethods(encryptor encryption.FieldEncryptor) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	if t.PrivateKey != "" {
		signer, err := t.buildPrivateKeySigner(encryptor)
		if err != nil {
			return nil, err
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if t.Password != "" {
		password, err := encryptor.Decrypt(t.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt SSH tunnel password: %w", err)
		}

		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, ErrNoAuthMethod
	}

	return authMethods, nil
}

func (t *Tunnel) buildPrivateKeySigner(encryptor encryption.FieldEncryptor) (ssh.Signer, error) {
	privateKey, err := encryptor.Decrypt(t.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH tunnel private key: %w", err)
	}

	if t.PrivateKeyPassphrase == "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH tunnel private key: %w", err)
		}

		return signer, nil
	}

	passphrase, err := encryptor.Decrypt(t.PrivateKeyPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH tunnel private key passphrase: %w", err)
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH tunnel private key: %w", err)
	}

	return signer, nil
}

func (t *Tunnel) buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	if t.ShouldSkipHostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if t.HostKeyFingerprint == "" {
		return nil, ErrHostKeyFingerprintMissing
	}

	expectedFingerprint := t.HostKeyFingerprint

	return func(_ string, _ net.Addr, hostKey ssh.PublicKey) error {
		if ssh.FingerprintSHA256(hostKey) != expectedFingerprint {
			return ErrHostKeyMismatch
		}

		return nil
	}, nil
}

func (o *OpenedTunnel) GetLocalEndpoint() (host string, port int) {
	return o.localHost, o.localPort
}

func (o *OpenedTunnel) Close() error {
	o.closeOnce.Do(func() {
		closeErr := o.listener.Close()
		o.acceptLoop.Wait()

		o.stopForwarding()

		if err := o.sshClient.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}

		o.forwardedConnections.Wait()

		o.closeErr = closeErr
	})

	return o.closeErr
}

func (o *OpenedTunnel) acceptConnections() {
	for {
		localConn, err := o.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				o.logger.Error("ssh tunnel stopped accepting local connections", "error", err)
			}

			return
		}

		o.forwardedConnections.Go(func() { o.forwardConnection(localConn) })
	}
}

func (o *OpenedTunnel) forwardConnection(localConn net.Conn) {
	defer func() { _ = localConn.Close() }()

	remoteConn, err := o.sshClient.Dial("tcp", o.remoteAddress)
	if err != nil {
		o.logger.Error("failed to reach the tunnel destination", "error", err)

		return
	}
	defer func() { _ = remoteConn.Close() }()

	stopWatchingShutdown := context.AfterFunc(o.forwardingCtx, func() {
		_ = localConn.Close()
		_ = remoteConn.Close()
	})
	defer stopWatchingShutdown()

	var copies sync.WaitGroup

	copies.Go(func() {
		_, _ = io.Copy(remoteConn, localConn)
		halfCloseWrites(remoteConn)
	})

	copies.Go(func() {
		_, _ = io.Copy(localConn, remoteConn)
		halfCloseWrites(localConn)
	})

	copies.Wait()
}

func halfCloseWrites(conn net.Conn) {
	halfCloser, canHalfClose := conn.(writeHalfCloser)
	if !canHalfClose {
		_ = conn.Close()

		return
	}

	_ = halfCloser.CloseWrite()
}
