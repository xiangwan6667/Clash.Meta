package tls

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/metacubex/mldsa"
	utls "github.com/metacubex/utls"
)

func TestRealityVerifierMLDSA65(t *testing.T) {
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherSeed := make([]byte, 32)
	otherSeed[0] = 1
	otherKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authKey := []byte("test REALITY authentication key")
	clientHello := []byte("encrypted client hello")
	serverHello := []byte("server hello")
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	certSignature := h.Sum(nil)
	h.Write(clientHello)
	h.Write(serverHello)
	pqSignature, err := privateKey.SignDeterministic(h.Sum(nil), nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		key           *mldsa.PublicKey
		pqSignature   []byte
		clientHello   []byte
		certSignature []byte
		wantError     bool
	}{
		{name: "legacy without pin", certSignature: certSignature},
		{name: "signed without pin", certSignature: certSignature, pqSignature: pqSignature},
		{name: "valid signature", key: privateKey.PublicKey(), certSignature: certSignature, pqSignature: pqSignature},
		{name: "missing signature", key: privateKey.PublicKey(), certSignature: certSignature, wantError: true},
		{name: "wrong public key", key: otherKey.PublicKey(), certSignature: certSignature, pqSignature: pqSignature, wantError: true},
		{name: "tampered transcript", key: privateKey.PublicKey(), certSignature: certSignature, pqSignature: pqSignature, clientHello: []byte("different hello"), wantError: true},
		{name: "tampered signature", key: privateKey.PublicKey(), certSignature: certSignature, pqSignature: append([]byte(nil), pqSignature[:len(pqSignature)-1]...), wantError: true},
		{name: "wrong reality authentication", key: privateKey.PublicKey(), certSignature: make([]byte, len(certSignature)), pqSignature: pqSignature, wantError: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			uConn := utls.UClient(client, &utls.Config{}, utls.HelloChrome_Auto)
			hello := clientHello
			if tt.clientHello != nil {
				hello = tt.clientHello
			}
			uConn.HandshakeState.Hello.Raw = hello
			uConn.HandshakeState.ServerHello = &utls.PubServerHelloMsg{Raw: serverHello}
			cert := &x509.Certificate{PublicKey: pub, Signature: tt.certSignature}
			if tt.pqSignature != nil {
				cert.Extensions = []pkix.Extension{{Id: []int{0, 0}, Value: tt.pqSignature}}
			}
			verifier := &realityVerifier{UConn: uConn, authKey: authKey, mldsa65Verify: tt.key}
			err := verifier.VerifyConnection(utls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
			if (err != nil) != tt.wantError {
				t.Fatalf("VerifyConnection() error = %v, want error %v", err, tt.wantError)
			}
			if verifier.verified == tt.wantError {
				t.Fatalf("verified = %v, want %v", verifier.verified, !tt.wantError)
			}
		})
	}

	t.Run("shared verification key in concurrent handshakes", func(t *testing.T) {
		key := privateKey.PublicKey()
		cert := &x509.Certificate{
			PublicKey: pub, Signature: certSignature,
			Extensions: []pkix.Extension{{Id: []int{0, 0}, Value: pqSignature}},
		}
		const clients = 24
		failures := make(chan error, clients)
		var done sync.WaitGroup
		for i := 0; i < clients; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				uConn := utls.UClient(client, &utls.Config{}, utls.HelloChrome_Auto)
				uConn.HandshakeState.Hello.Raw = clientHello
				uConn.HandshakeState.ServerHello = &utls.PubServerHelloMsg{Raw: serverHello}
				verifier := &realityVerifier{UConn: uConn, authKey: authKey, mldsa65Verify: key}
				if err := verifier.VerifyConnection(utls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil || !verifier.verified {
					failures <- fmt.Errorf("verification failed: %v", err)
				}
			}()
		}
		done.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	})
}

func BenchmarkRealityVerifier(b *testing.B) {
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	authKey := []byte("test REALITY authentication key")
	clientHello, serverHello := []byte("client hello"), []byte("server hello")
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	cert := &x509.Certificate{PublicKey: pub, Signature: h.Sum(nil)}
	h.Write(clientHello)
	h.Write(serverHello)
	signature, err := privateKey.SignDeterministic(h.Sum(nil), nil)
	if err != nil {
		b.Fatal(err)
	}
	cert.Extensions = []pkix.Extension{{Id: []int{0, 0}, Value: signature}}
	state := utls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	for _, tt := range []struct {
		name string
		key  *mldsa.PublicKey
	}{
		{name: "legacy"},
		{name: "mldsa65", key: privateKey.PublicKey()},
	} {
		b.Run(tt.name, func(b *testing.B) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			uConn := utls.UClient(client, &utls.Config{}, utls.HelloChrome_Auto)
			uConn.HandshakeState.Hello.Raw = clientHello
			uConn.HandshakeState.ServerHello = &utls.PubServerHelloMsg{Raw: serverHello}
			verifier := &realityVerifier{UConn: uConn, authKey: authKey, mldsa65Verify: tt.key}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := verifier.VerifyConnection(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
