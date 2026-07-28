package ssh_tunnel_testing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	BastionUsername      = "bastion-user"
	BastionPassword      = "bastion-password"
	PrivateKeyPassphrase = "private-key-passphrase"
	NetworkTimeout       = 5 * time.Second

	loopbackHost = "127.0.0.1"
)

// An in-process bastion keeps tunnel tests deterministic and container-free; it speaks only the
// direct-tcpip channel the forwarder uses.
type Bastion struct {
	listener      net.Listener
	hostKey       ssh.Signer
	serverConfig  *ssh.ServerConfig
	acceptLoop    sync.WaitGroup
	connections   sync.WaitGroup
	openedTracker ConnectionTracker

	bytesRelayedFromRemote atomic.Int64
}

func StartBastion(t *testing.T, authorizedKey ssh.PublicKey) *Bastion {
	t.Helper()

	hostKey := generateHostKey(t)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(connMetadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if connMetadata.User() != BastionUsername || string(password) != BastionPassword {
				return nil, errors.New("invalid password credentials")
			}

			return nil, nil
		},
	}

	if authorizedKey != nil {
		serverConfig.PublicKeyCallback = func(
			connMetadata ssh.ConnMetadata,
			offeredKey ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if connMetadata.User() != BastionUsername ||
				!bytes.Equal(offeredKey.Marshal(), authorizedKey.Marshal()) {
				return nil, errors.New("unauthorized public key")
			}

			return nil, nil
		}
	}

	serverConfig.AddHostKey(hostKey)

	listenConfig := net.ListenConfig{}

	listener, err := listenConfig.Listen(t.Context(), "tcp", net.JoinHostPort(loopbackHost, "0"))
	require.NoError(t, err)

	bastion := &Bastion{listener: listener, hostKey: hostKey, serverConfig: serverConfig}
	bastion.acceptLoop.Go(bastion.acceptConnections)

	t.Cleanup(bastion.stop)

	return bastion
}

func (b *Bastion) GetHost() string {
	return loopbackHost
}

func (b *Bastion) GetPort() int {
	return GetListenerPort(b.listener)
}

func (b *Bastion) GetHostKeyFingerprint() string {
	return ssh.FingerprintSHA256(b.hostKey.PublicKey())
}

// Callers that must prove a subprocess really crossed the bastion compare this against the volume
// only that subprocess could have moved — a channel count cannot tell the payload apart from the
// short metadata probes the Go drivers run over the same tunnel.
func (b *Bastion) GetBytesRelayedFromRemote() int64 {
	return b.bytesRelayedFromRemote.Load()
}

func (b *Bastion) RequireConnectionsFinished(t *testing.T) {
	t.Helper()

	finished := make(chan struct{})

	go func() {
		b.connections.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(NetworkTimeout):
		t.Fatal("the SSH server still holds a connection the client should have closed")
	}
}

func (b *Bastion) acceptConnections() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}

		b.openedTracker.Track(conn)
		b.connections.Go(func() { b.serveConnection(conn) })
	}
}

func (b *Bastion) serveConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	serverConn, newChannels, globalRequests, err := ssh.NewServerConn(conn, b.serverConfig)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()

	b.connections.Go(func() { ssh.DiscardRequests(globalRequests) })

	for newChannel := range newChannels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip channels are supported")

			continue
		}

		b.connections.Go(func() { b.serveDirectTcpipChannel(newChannel) })
	}
}

func (b *Bastion) serveDirectTcpipChannel(newChannel ssh.NewChannel) {
	var request directTcpipRequest
	if err := ssh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")

		return
	}

	destinationAddress := net.JoinHostPort(request.DestinationHost, strconv.Itoa(int(request.DestinationPort)))

	dialer := net.Dialer{Timeout: NetworkTimeout}

	destinationConn, err := dialer.DialContext(context.Background(), "tcp", destinationAddress)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "destination is unreachable")

		return
	}
	defer func() { _ = destinationConn.Close() }()

	b.openedTracker.Track(destinationConn)

	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()

	b.connections.Go(func() { ssh.DiscardRequests(channelRequests) })

	var copies sync.WaitGroup

	copies.Go(func() {
		_, _ = io.Copy(destinationConn, channel)

		if tcpConn, isTcpConn := destinationConn.(*net.TCPConn); isTcpConn {
			_ = tcpConn.CloseWrite()
		}
	})

	copies.Go(func() {
		relayedBytes, _ := io.Copy(channel, destinationConn)
		b.bytesRelayedFromRemote.Add(relayedBytes)

		_ = channel.CloseWrite()
	})

	copies.Wait()
}

func (b *Bastion) stop() {
	_ = b.listener.Close()
	b.acceptLoop.Wait()

	b.openedTracker.CloseAll()
	b.connections.Wait()
}

type directTcpipRequest struct {
	DestinationHost string
	DestinationPort uint32
	OriginHost      string
	OriginPort      uint32
}

type ConnectionTracker struct {
	mutex              sync.Mutex
	trackedConnections []net.Conn
}

func (c *ConnectionTracker) Track(conn net.Conn) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.trackedConnections = append(c.trackedConnections, conn)
}

func (c *ConnectionTracker) CloseAll() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, conn := range c.trackedConnections {
		_ = conn.Close()
	}

	c.trackedConnections = nil
}

func GenerateHostKeyFingerprint(t *testing.T) string {
	t.Helper()

	return ssh.FingerprintSHA256(generateHostKey(t).PublicKey())
}

func GenerateProtectedClientKey(t *testing.T) (privateKeyPem string, authorizedKey ssh.PublicKey) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(PrivateKeyPassphrase))
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(pemBlock)), signer.PublicKey()
}

func GetListenerPort(listener net.Listener) int {
	tcpAddress, isTcpAddress := listener.Addr().(*net.TCPAddr)
	if !isTcpAddress {
		return 0
	}

	return tcpAddress.Port
}

func generateHostKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	hostKey, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)

	return hostKey
}
