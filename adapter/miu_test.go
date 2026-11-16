package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseMiu(t *testing.T) {
	config := map[string]any{
		"name": "miu-test", "type": "miu", "server": "example.com",
		"port": 443, "psk": "0123456789abcdef", "udp": true,
	}
	proxy, err := ParseProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.Type() != C.Miu || !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatalf("unexpected adapter: type=%s udp=%v uot=%v", proxy.Type(), proxy.SupportUDP(), proxy.SupportUOT())
	}
	delete(config, "psk")
	if _, err := ParseProxy(config); err == nil {
		t.Fatal("missing PSK was accepted")
	}
}
