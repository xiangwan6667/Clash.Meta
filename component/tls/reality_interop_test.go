package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

const realityTestServerName = "reality.example.test"

var realityTestShortID = [8]byte{1, 35, 69, 103, 137, 171, 205, 239}

// The target's long certificate also accommodates Xray's optional ML-DSA signature.
func realityTestTarget(t *testing.T, curves []utls.CurveID) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{realityTestServerName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: make([]byte, 4000)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	config := &utls.Config{
		Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   utls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, CurvePreferences: curves,
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Xray probes target post-handshake records asynchronously at startup.
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				server := utls.Server(conn, config)
				var data [1]byte
				server.Read(data[:])
			}()
		}
	}()
	return listener.Addr().String()
}

func TestRealityExistingServerInterop(t *testing.T) {
	for _, tt := range []struct {
		name    string
		support bool
		curve   utls.CurveID
	}{
		{name: "legacy default", curve: utls.X25519},
		{name: "hybrid key exchange", support: true, curve: utls.X25519MLKEM768},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			target := realityTestTarget(t, []utls.CurveID{utls.X25519MLKEM768, utls.X25519})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				dialer := &net.Dialer{}
				server, err := utls.RealityServer(context.Background(), raw, &utls.RealityConfig{
					DialContext: dialer.DialContext, Type: "tcp", Dest: target,
					ServerNames: map[string]bool{realityTestServerName: true},
					PrivateKey:  privateKey.Bytes(), ShortIds: map[[8]byte]bool{realityTestShortID: true},
					Config: utls.Config{SessionTicketsDisabled: true},
				})
				if err != nil {
					serverDone <- err
					return
				}
				var payload [4]byte
				if _, err = io.ReadFull(server, payload[:]); err == nil && string(payload[:]) == "ping" {
					_, err = server.Write([]byte("pong"))
				}
				serverDone <- err
			}()

			raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := GetRealityConn(ctx, raw, utls.HelloChrome_Auto, realityTestServerName, &RealityConfig{
				PublicKey: privateKey.PublicKey(), ShortID: realityTestShortID, SupportX25519MLKEM768: tt.support,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if group := client.(*utls.UConn).HandshakeState.ServerHello.ServerShare.Group; group != tt.curve {
				t.Fatalf("negotiated group = %v, want %v", group, tt.curve)
			}
			if _, err = client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var response [4]byte
			if _, err = io.ReadFull(client, response[:]); err != nil || string(response[:]) != "pong" {
				t.Fatalf("response = %q, error = %v", response, err)
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
