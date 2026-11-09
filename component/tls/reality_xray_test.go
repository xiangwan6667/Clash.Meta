package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mldsa"
	utls "github.com/metacubex/utls"
)

// Set XRAY_REALITY_INTEROP to a locally built official Xray binary to run these
// tests. Set XRAY_REALITY_OLD_INTEROP to official Xray 25.3.31 to exercise
// servers predating hybrid key exchange. Tests neither link nor download Xray.
func TestRealityXrayServerInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_REALITY_INTEROP")
	if xrayBinary == "" {
		t.Skip("set XRAY_REALITY_INTEROP to the official Xray executable")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRealityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrongSeed := make([]byte, 32)
	wrongSeed[0] = 1
	wrongKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), wrongSeed)
	if err != nil {
		t.Fatal(err)
	}
	version := [3]byte{26, 3, 27}
	echo := realityTestEcho(t)

	for _, server := range []struct {
		name    string
		signed  bool
		minimum string
		curves  []utls.CurveID
		group   utls.CurveID
	}{
		{name: "signed hybrid", signed: true, curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, group: utls.X25519MLKEM768},
		{name: "unsigned classical", curves: []utls.CurveID{utls.X25519}, group: utls.X25519},
		{name: "version minimum", minimum: "26.3.27", curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, group: utls.X25519MLKEM768},
	} {
		server := server
		t.Run(server.name, func(t *testing.T) {
			target := realityTestTarget(t, server.curves)
			addr := realityTestXrayServer(t, xrayBinary, target, privateKey, server.signed, server.minimum)
			for _, tc := range []struct {
				name        string
				fingerprint utls.ClientHelloID
				hybrid      bool
				pin         *mldsa.PublicKey
				version     *[3]byte
				wrongID     bool
				wrongKey    bool
				wantSuccess bool
			}{
				{name: "legacy no pin", fingerprint: utls.HelloChrome_Auto, hybrid: true, wantSuccess: server.minimum == ""},
				{name: "correct pin", fingerprint: utls.HelloChrome_Auto, hybrid: true, pin: signingKey.PublicKey(), wantSuccess: server.signed && server.minimum == ""},
				{name: "wrong pin", fingerprint: utls.HelloChrome_Auto, hybrid: true, pin: wrongKey.PublicKey()},
				{name: "wrong short ID", fingerprint: utls.HelloChrome_Auto, hybrid: true, wrongID: true},
				{name: "wrong REALITY key", fingerprint: utls.HelloChrome_Auto, hybrid: true, wrongKey: true},
				{name: "compatible version", fingerprint: utls.HelloChrome_Auto, hybrid: true, version: &version, wantSuccess: true},
				{name: "hybrid disabled", fingerprint: utls.HelloChrome_Auto},
				{name: "classic fingerprint", fingerprint: utls.HelloChrome_120, hybrid: true},
			} {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					// Xray may wait for its startup target probe in 5-second intervals.
					raw.SetDeadline(time.Now().Add(20 * time.Second))
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					publicKey := privateKey.PublicKey()
					if tc.wrongKey {
						publicKey = wrongRealityKey.PublicKey()
					}
					shortID := realityTestShortID
					if tc.wrongID {
						shortID[0] ^= 1
					}
					conn, err := GetRealityConn(ctx, raw, tc.fingerprint, realityTestServerName, &RealityConfig{
						PublicKey: publicKey, ShortID: shortID,
						SupportX25519MLKEM768: tc.hybrid, Mldsa65Verify: tc.pin, ClientVersion: tc.version,
					})
					if !tc.wantSuccess {
						if err == nil {
							conn.Close()
							t.Fatal("expected the REALITY handshake to fail")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if group := conn.(*utls.UConn).HandshakeState.ServerHello.ServerShare.Group; group != server.group {
						t.Fatalf("negotiated group = %v, want %v", group, server.group)
					}
					realityTestVLESSExchange(t, conn, echo)
				})
			}
		})
	}
}

func TestRealityOldXrayServerInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_REALITY_OLD_INTEROP")
	if xrayBinary == "" {
		t.Skip("set XRAY_REALITY_OLD_INTEROP to an older official Xray executable")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echo := realityTestEcho(t)
	for _, server := range []struct {
		name   string
		curves []utls.CurveID
	}{
		{name: "classical target", curves: []utls.CurveID{utls.X25519}},
		{name: "hybrid target", curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}},
	} {
		server := server
		t.Run(server.name, func(t *testing.T) {
			target := realityTestTarget(t, server.curves)
			addr := realityTestXrayServer(t, xrayBinary, target, privateKey, false, "")
			for _, hybrid := range []bool{false, true} {
				hybrid := hybrid
				t.Run(fmt.Sprintf("hybrid=%t", hybrid), func(t *testing.T) {
					raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					raw.SetDeadline(time.Now().Add(10 * time.Second))
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					conn, err := GetRealityConn(ctx, raw, utls.HelloChrome_Auto, realityTestServerName, &RealityConfig{
						PublicKey: privateKey.PublicKey(), ShortID: realityTestShortID, SupportX25519MLKEM768: hybrid,
					})
					if hybrid && server.name == "hybrid target" {
						if err == nil {
							conn.Close()
							t.Fatal("older Xray unexpectedly accepted the target's hybrid server hello")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if group := conn.(*utls.UConn).HandshakeState.ServerHello.ServerShare.Group; group != utls.X25519 {
						t.Fatalf("negotiated group = %v, want X25519", group)
					}
					realityTestVLESSExchange(t, conn, echo)
				})
			}
		})
	}
}

func TestRealityXrayClientInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_REALITY_INTEROP")
	if xrayBinary == "" {
		t.Skip("set XRAY_REALITY_INTEROP to the official Xray executable")
	}
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
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		dialer := &net.Dialer{}
		conn, err := utls.RealityServer(context.Background(), raw, &utls.RealityConfig{
			DialContext: dialer.DialContext, Type: "tcp", Dest: target,
			ServerNames: map[string]bool{realityTestServerName: true},
			PrivateKey:  privateKey.Bytes(), ShortIds: map[[8]byte]bool{realityTestShortID: true},
			Config: utls.Config{SessionTicketsDisabled: true},
		})
		if err != nil {
			serverDone <- err
			return
		}
		// Read and validate a VLESS request for an IPv4 TCP target.
		var header [18]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			serverDone <- err
			return
		}
		want := []byte{0, 0xa1, 0xb2, 0xc3, 0xd4, 0xea, 0xcc, 0x44, 0x33, 0x98, 0x1b, 0x7e, 0x5f, 0x9a, 0x8b, 0x12, 0x34, 0}
		if !bytes.Equal(header[:], want) {
			serverDone <- fmt.Errorf("unexpected VLESS header: %x", header)
			return
		}
		var destination [8]byte
		if _, err = io.ReadFull(conn, destination[:]); err != nil {
			serverDone <- err
			return
		}
		if destination[0] != 1 || destination[3] != 1 {
			serverDone <- fmt.Errorf("unexpected VLESS destination: %x", destination)
			return
		}
		if _, err = conn.Write([]byte{0, 0}); err == nil {
			var payload [4]byte
			if _, err = io.ReadFull(conn, payload[:]); err == nil {
				_, err = conn.Write(payload[:])
			}
		}
		serverDone <- err
	}()

	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := socks.Addr().(*net.TCPAddr).Port
	socks.Close()
	config := map[string]any{
		"log": map[string]any{"loglevel": "info", "access": "none"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"address": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port,
				"id": "a1b2c3d4-eacc-4433-981b-7e5f9a8b1234", "encryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"serverName": realityTestServerName, "fingerprint": "chrome",
					"password": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), "shortId": "0123456789abcdef",
				},
			},
		}},
	}
	addr := realityTestStartXray(t, xrayBinary, socksPort, config)
	client, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err = io.ReadFull(client, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting = %x, error = %v", greeting, err)
	}
	if _, err = client.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err = io.ReadFull(client, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("SOCKS reply = %x, error = %v", reply, err)
	}
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err = io.ReadFull(client, response[:]); err != nil || string(response[:]) != "ping" {
		t.Fatalf("reverse VLESS response = %q, error = %v", response, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func realityTestXrayServer(t *testing.T, executable, target string, key *ecdh.PrivateKey, signed bool, minimum string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	reality := map[string]any{
		"target": target, "dest": target, "serverNames": []string{realityTestServerName},
		"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()),
		"shortIds":   []string{"0123456789abcdef"},
	}
	if signed {
		reality["mldsa65Seed"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	}
	if minimum != "" {
		reality["minClientVer"] = minimum
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "info", "access": "none"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": "a1b2c3d4-eacc-4433-981b-7e5f9a8b1234"}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": reality},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}},
		}},
	}
	return realityTestStartXray(t, executable, port, config)
}

func realityTestStartXray(t *testing.T, executable string, port int, config map[string]any) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "run", "-c", path)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("Xray output:\n%s", output.String())
		}
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("official Xray server did not start")
	return ""
}

func realityTestEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func realityTestVLESSExchange(t *testing.T, conn net.Conn, echo string) {
	t.Helper()
	_, portString, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{0, 0xa1, 0xb2, 0xc3, 0xd4, 0xea, 0xcc, 0x44, 0x33, 0x98, 0x1b, 0x7e, 0x5f, 0x9a, 0x8b, 0x12, 0x34}
	request = append(request, 0, 1, byte(port>>8), byte(port), 1, 127, 0, 0, 1)
	request = append(request, "ping"...)
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var response [6]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "\x00\x00ping" {
		t.Fatalf("VLESS echo response = %q, error = %v", response, err)
	}
}
