// Tests adapted from MiuProtocol/Miu; see transport/miu/LICENSE.
package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/miu"
)

// Raw segments reach into the TLS connections of metacubex/tls and metacubex/utls. If this fails after
// one of them has been upgraded, Miu still works, but without raw segments.
func TestMiuRawSegmentsUsable(t *testing.T) {
	if !miuRawUsable() {
		t.Fatal("the Miu self-test failed: raw segments would be disabled")
	}
}

func TestMiuOption(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	parse := func(mapping map[string]any) (*Miu, error) {
		option := &MiuOption{}
		if err := decoder.Decode(mapping, option); err != nil {
			return nil, err
		}
		return NewMiu(*option)
	}
	base := func() map[string]any {
		return map[string]any{"name": "n", "type": "miu", "server": "example.com", "port": 443, "psk": "0123456789abcdef0123456789abcdef", "udp": true, "tls": true}
	}

	m, err := parse(base())
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != C.Miu || m.Type().String() != "Miu" || !m.SupportUDP() || m.Addr() != "example.com:443" || m.tlsConfig.Host != "example.com" {
		t.Fatalf("type %v, udp %v, addr %s, sni %s", m.Type(), m.SupportUDP(), m.Addr(), m.tlsConfig.Host)
	}
	_ = m.Close()

	for _, key := range []string{"sni", "servername"} {
		mapping := base()
		mapping[key] = "www.example.com"
		m, err := parse(mapping)
		if err != nil || m.tlsConfig.Host != "www.example.com" {
			t.Fatalf("%s: %v", key, err)
		}
		_ = m.Close()
	}

	reality := base()
	reality["reality-opts"] = map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "0123456789abcdef"}
	if _, err := parse(reality); err == nil {
		t.Fatal("reality-opts without client-fingerprint was accepted")
	}
	reality["client-fingerprint"] = "chrome"
	m, err = parse(reality)
	if err != nil || m.tlsConfig.Reality == nil {
		t.Fatalf("reality: %v", err)
	}
	_ = m.Close()
	reality["client-fingerprint"] = "none"
	if _, err := parse(reality); err == nil {
		t.Fatal("REALITY without a usable fingerprint was accepted")
	}

	short := base()
	short["psk"] = "short"
	if _, err := parse(short); err == nil {
		t.Fatal("a psk shorter than 16 characters was accepted")
	}
	missing := base()
	delete(missing, "psk")
	if _, err := parse(missing); err == nil {
		t.Fatal("a proxy without psk was accepted")
	}
}

func TestMiuInvalidOptions(t *testing.T) {
	valid := MiuOption{Name: "n", Server: "example.com", Port: 443, PSK: "0123456789abcdef"}
	tests := map[string]func(*MiuOption){
		"empty name":                  func(o *MiuOption) { o.Name = " " },
		"empty server":                func(o *MiuOption) { o.Server = "" },
		"port zero":                   func(o *MiuOption) { o.Port = 0 },
		"port too high":               func(o *MiuOption) { o.Port = 65536 },
		"short psk":                   func(o *MiuOption) { o.PSK = "short" },
		"bad fingerprint":             func(o *MiuOption) { o.ClientFingerprint = "invalid" },
		"short ID without public key": func(o *MiuOption) { o.RealityOpts.ShortID = "01" },
		"negative idle timeout":       func(o *MiuOption) { o.IdleSessionTimeout = -1 },
		"negative idle count":         func(o *MiuOption) { o.MinIdleSession = -1 },
		"excessive idle count":        func(o *MiuOption) { o.MinIdleSession = 33 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			option := valid
			change(&option)
			if proxy, err := NewMiu(option); err == nil {
				_ = proxy.Close()
				t.Fatal("invalid option was accepted")
			}
		})
	}
}

func TestMiuRejectsTLS12BeforeAuthentication(t *testing.T) {
	cert, err := miu.SelfSignedCert("miu.test")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		var b [1]byte
		n, err := server.Read(b[:])
		if n != 0 || err == nil {
			serverDone <- errors.New("client sent authentication data over TLS 1.2")
			return
		}
		serverDone <- nil
	}()
	m, err := NewMiu(MiuOption{Name: "test", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, PSK: "0123456789abcdef", SNI: "miu.test", SkipCertVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := m.dialLane(ctx)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "must use TLS 1.3") {
		t.Fatalf("expected TLS 1.2 rejection, got %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestMiuDialCanceled(t *testing.T) {
	proxy, err := NewMiu(MiuOption{Name: "test", Server: "127.0.0.1", Port: 443, PSK: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 443})
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
}
