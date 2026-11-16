package outbound

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mldsa"
)

func TestVlessRealityHybridDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   any
		present bool
		want    bool
	}{
		{name: "omitted", want: true},
		{name: "null", present: true, want: true},
		{name: "enabled", value: true, present: true, want: true},
		{name: "disabled", value: false, present: true},
		{name: "one", value: 1, present: true, want: true},
		{name: "zero", value: 0, present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reality := map[string]any{
				"public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
			}
			if tc.present {
				reality["support-x25519mlkem768"] = tc.value
			}
			mapping := map[string]any{
				"name": "reality-defaults", "server": "127.0.0.1", "port": 443,
				"uuid": "a1b2c3d4-eacc-4433-981b-7e5f9a8b1234",
				"tls":  true, "client-fingerprint": "chrome", "reality-opts": reality,
			}
			decoder := structure.NewDecoder(structure.Option{
				TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer,
			})
			var option VlessOption
			if err := decoder.Decode(mapping, &option); err != nil {
				t.Fatal(err)
			}
			proxy, err := NewVless(option)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if proxy.realityConfig == nil {
				t.Fatal("missing REALITY configuration")
			}
			if got := proxy.realityConfig.SupportX25519MLKEM768; got != tc.want {
				t.Fatalf("hybrid key exchange = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRealityOptionsCompatibility(t *testing.T) {
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifyKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	supportHybrid := true
	config, err := (RealityOptions{PublicKey: publicKey, ShortID: "0123", Mldsa65Verify: verifyKey, ClientVersion: "26.3.27", SupportX25519MLKEM768: &supportHybrid}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.Mldsa65Verify == nil || !config.Mldsa65Verify.Equal(privateKey.PublicKey()) {
		t.Fatal("ML-DSA-65 public key was not preserved")
	}
	if config.ClientVersion == nil || *config.ClientVersion != [3]byte{26, 3, 27} || !config.SupportX25519MLKEM768 {
		t.Fatal("REALITY compatibility settings were not preserved")
	}
	legacy, err := (RealityOptions{PublicKey: publicKey}).Parse()
	if err != nil || legacy == nil || legacy.ClientVersion != nil || legacy.Mldsa65Verify != nil || !legacy.SupportX25519MLKEM768 {
		t.Fatalf("unexpected REALITY defaults: config=%+v error=%v", legacy, err)
	}
	versionZero, err := (RealityOptions{PublicKey: publicKey, ClientVersion: "0.0.0"}).Parse()
	if err != nil || versionZero.ClientVersion == nil || *versionZero.ClientVersion != [3]byte{} {
		t.Fatalf("zero version was not preserved: config=%+v error=%v", versionZero, err)
	}
	versionMax, err := (RealityOptions{PublicKey: publicKey, ClientVersion: "255.255.255"}).Parse()
	if err != nil || versionMax.ClientVersion == nil || *versionMax.ClientVersion != [3]byte{255, 255, 255} {
		t.Fatalf("maximum version was not preserved: config=%+v error=%v", versionMax, err)
	}

	for _, option := range []RealityOptions{
		{Mldsa65Verify: verifyKey},
		{ClientVersion: "26.3.27"},
		{PublicKey: publicKey, Mldsa65Verify: "%%%"},
		{PublicKey: publicKey, Mldsa65Verify: strings.Repeat("!", base64.RawURLEncoding.EncodedLen(mldsa.MLDSA65PublicKeySize))},
		{PublicKey: publicKey, Mldsa65Verify: base64.RawURLEncoding.EncodeToString(make([]byte, 1951))},
		{PublicKey: publicKey, ClientVersion: "26.3"},
		{PublicKey: publicKey, ClientVersion: "26.3.27.0"},
		{PublicKey: publicKey, ClientVersion: "26.-1.27"},
		{PublicKey: publicKey, ClientVersion: "256.0.0"},
		{PublicKey: publicKey, ClientVersion: "26..27"},
	} {
		if _, err := option.Parse(); err == nil {
			t.Errorf("invalid REALITY options accepted: %+v", option)
		}
	}
}
