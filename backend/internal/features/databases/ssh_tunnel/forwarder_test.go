package ssh_tunnel

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	ssh_tunnel_testing "databasus-backend/internal/features/databases/ssh_tunnel/testing"
)

const testEncryptionPrefix = "encrypted:"

func Test_OpenTunnel_WithValidCredentials_ForwardsTrafficToRemote(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	require.NoError(t, sshTunnel.Validate())

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	require.NoError(t, err)

	localHost, localPort := openedTunnel.GetLocalEndpoint()
	assert.Equal(t, loopbackHost, localHost)
	assert.Positive(t, localPort)

	assert.Equal(t, "hello through the tunnel", sendThroughTunnel(t, openedTunnel, "hello through the tunnel"))

	require.NoError(t, openedTunnel.Close())
	requireNoForwardingGoroutines(t)
}

func Test_OpenTunnel_WithPassphraseProtectedPrivateKey_ForwardsTrafficToRemote(t *testing.T) {
	privateKeyPem, authorizedKey := ssh_tunnel_testing.GenerateProtectedClientKey(t)

	testbed := startForwardingTestbed(t, authorizedKey)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.Password = ""
	sshTunnel.PrivateKey = encryptTestValue(privateKeyPem)
	sshTunnel.PrivateKeyPassphrase = encryptTestValue(ssh_tunnel_testing.PrivateKeyPassphrase)

	require.NoError(t, sshTunnel.Validate())

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	require.NoError(t, err)

	assert.Equal(t, "hello over public key auth", sendThroughTunnel(t, openedTunnel, "hello over public key auth"))

	require.NoError(t, openedTunnel.Close())
	requireNoForwardingGoroutines(t)
}

func Test_OpenTunnel_WhenHostKeyCheckIsSkipped_ForwardsTrafficToRemote(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.HostKeyFingerprint = ""
	sshTunnel.ShouldSkipHostKeyCheck = true

	require.NoError(t, sshTunnel.Validate())

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	require.NoError(t, err)

	assert.Equal(t, "hello without host key check", sendThroughTunnel(t, openedTunnel, "hello without host key check"))

	require.NoError(t, openedTunnel.Close())
	requireNoForwardingGoroutines(t)
}

func Test_OpenTunnel_WhenHostKeyMismatches_ReturnsErrorAndLeaksNothing(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.HostKeyFingerprint = ssh_tunnel_testing.GenerateHostKeyFingerprint(t)

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	require.Error(t, err)
	assert.Nil(t, openedTunnel)
	assert.ErrorIs(t, err, ErrHostKeyMismatch)
	assert.NotContains(t, err.Error(), ssh_tunnel_testing.BastionPassword)

	requireNoForwardingGoroutines(t)
	testbed.bastion.RequireConnectionsFinished(t)
}

func Test_OpenTunnel_WithoutHostKeyFingerprint_ReturnsError(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.HostKeyFingerprint = ""

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	assert.Nil(t, openedTunnel)
	assert.ErrorIs(t, err, ErrHostKeyFingerprintMissing)
}

func Test_OpenTunnel_WithoutPasswordAndPrivateKey_ReturnsError(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.Password = ""

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	assert.Nil(t, openedTunnel)
	assert.ErrorIs(t, err, ErrNoAuthMethod)
}

func Test_OpenTunnel_WithWrongPassword_ReturnsErrorAndLeaksNothing(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	sshTunnel := testbed.NewPasswordTunnel()
	sshTunnel.Password = encryptTestValue("not-the-bastion-password")

	openedTunnel, err := sshTunnel.Open(t.Context(), testbed.GetForwardSpec())
	require.Error(t, err)
	assert.Nil(t, openedTunnel)
	assert.NotContains(t, err.Error(), "not-the-bastion-password")

	requireNoForwardingGoroutines(t)
	testbed.bastion.RequireConnectionsFinished(t)
}

func Test_CloseTunnel_WithConnectionInFlight_WaitsForCopiesToFinish(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	openedTunnel, err := testbed.NewPasswordTunnel().Open(t.Context(), testbed.GetForwardSpec())
	require.NoError(t, err)

	localHost, localPort := openedTunnel.GetLocalEndpoint()

	inFlightConn, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(localHost, strconv.Itoa(localPort)),
		ssh_tunnel_testing.NetworkTimeout,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = inFlightConn.Close() })
	require.NoError(t, inFlightConn.SetDeadline(time.Now().Add(ssh_tunnel_testing.NetworkTimeout)))

	_, err = inFlightConn.Write([]byte("in flight"))
	require.NoError(t, err)

	relayedPayload := make([]byte, len("in flight"))
	_, err = io.ReadFull(inFlightConn, relayedPayload)
	require.NoError(t, err)
	require.Equal(t, "in flight", string(relayedPayload))

	closeResult := make(chan error, 1)
	go func() { closeResult <- openedTunnel.Close() }()

	select {
	case closeErr := <-closeResult:
		require.NoError(t, closeErr)
	case <-time.After(ssh_tunnel_testing.NetworkTimeout):
		t.Fatal("Close did not return while a forwarded connection was still open")
	}

	requireNoForwardingGoroutines(t)

	_, err = inFlightConn.Read(make([]byte, 1))
	assert.Error(t, err, "the forwarded connection must be torn down by Close")
}

func Test_CloseTunnel_WhenCalledTwice_ReturnsSameResult(t *testing.T) {
	testbed := startForwardingTestbed(t, nil)

	openedTunnel, err := testbed.NewPasswordTunnel().Open(t.Context(), testbed.GetForwardSpec())
	require.NoError(t, err)

	require.NoError(t, openedTunnel.Close())
	require.NoError(t, openedTunnel.Close())

	requireNoForwardingGoroutines(t)
}

type forwardingTestbed struct {
	bastion    *ssh_tunnel_testing.Bastion
	echoServer *tcpEchoServer
}

func startForwardingTestbed(t *testing.T, authorizedKey ssh.PublicKey) *forwardingTestbed {
	t.Helper()

	return &forwardingTestbed{
		bastion:    ssh_tunnel_testing.StartBastion(t, authorizedKey),
		echoServer: startTcpEchoServer(t),
	}
}

func (b *forwardingTestbed) GetForwardSpec() ForwardSpec {
	return ForwardSpec{
		Logger:     slog.New(slog.DiscardHandler),
		Encryptor:  prefixedFieldEncryptor{},
		RemoteHost: loopbackHost,
		RemotePort: b.echoServer.GetPort(),
	}
}

func (b *forwardingTestbed) NewPasswordTunnel() *Tunnel {
	return &Tunnel{
		Host:               b.bastion.GetHost(),
		Port:               b.bastion.GetPort(),
		Username:           ssh_tunnel_testing.BastionUsername,
		Password:           encryptTestValue(ssh_tunnel_testing.BastionPassword),
		HostKeyFingerprint: b.bastion.GetHostKeyFingerprint(),
	}
}

type prefixedFieldEncryptor struct{}

func (e prefixedFieldEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	return testEncryptionPrefix + plaintext, nil
}

func (e prefixedFieldEncryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	if !strings.HasPrefix(ciphertext, testEncryptionPrefix) {
		return "", errors.New("value was not encrypted before use")
	}

	return strings.TrimPrefix(ciphertext, testEncryptionPrefix), nil
}

type tcpEchoServer struct {
	listener      net.Listener
	acceptLoop    sync.WaitGroup
	connections   sync.WaitGroup
	openedTracker ssh_tunnel_testing.ConnectionTracker
}

func startTcpEchoServer(t *testing.T) *tcpEchoServer {
	t.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	require.NoError(t, err)

	echoServer := &tcpEchoServer{listener: listener}
	echoServer.acceptLoop.Go(echoServer.acceptConnections)

	t.Cleanup(echoServer.stop)

	return echoServer
}

func (s *tcpEchoServer) GetPort() int {
	return ssh_tunnel_testing.GetListenerPort(s.listener)
}

func (s *tcpEchoServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.openedTracker.Track(conn)
		s.connections.Go(func() {
			defer func() { _ = conn.Close() }()

			_, _ = io.Copy(conn, conn)
		})
	}
}

func (s *tcpEchoServer) stop() {
	_ = s.listener.Close()
	s.acceptLoop.Wait()

	s.openedTracker.CloseAll()
	s.connections.Wait()
}

func sendThroughTunnel(t *testing.T, openedTunnel *OpenedTunnel, payload string) string {
	t.Helper()

	localHost, localPort := openedTunnel.GetLocalEndpoint()

	conn, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(localHost, strconv.Itoa(localPort)),
		ssh_tunnel_testing.NetworkTimeout,
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.SetDeadline(time.Now().Add(ssh_tunnel_testing.NetworkTimeout)))

	_, err = conn.Write([]byte(payload))
	require.NoError(t, err)

	halfCloseWrites(conn)

	relayedPayload, err := io.ReadAll(conn)
	require.NoError(t, err)

	return string(relayedPayload)
}

func encryptTestValue(plaintext string) string {
	return testEncryptionPrefix + plaintext
}

// The shutdown watcher that context.AfterFunc starts can still be unwinding when Close returns, so
// only a frame that outlives the polling window is a leak.
func requireNoForwardingGoroutines(t *testing.T) {
	t.Helper()

	assert.Eventually(t, func() bool {
		stackDump := make([]byte, 1<<20)
		stackDump = stackDump[:runtime.Stack(stackDump, true)]

		for _, forwardingFunction := range []string{
			"ssh_tunnel.(*OpenedTunnel).acceptConnections",
			"ssh_tunnel.(*OpenedTunnel).forwardConnection",
		} {
			if strings.Contains(string(stackDump), forwardingFunction) {
				return false
			}
		}

		return true
	}, ssh_tunnel_testing.NetworkTimeout, 10*time.Millisecond, "leaked forwarding goroutine")
}
