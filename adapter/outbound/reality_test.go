package outbound

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mldsa"
)

func TestRealityOptionsCompatibility(t *testing.T) {
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifyKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	config, err := (RealityOptions{PublicKey: publicKey, ShortID: "0123", Mldsa65Verify: verifyKey, ClientVersion: "26.3.27", SupportX25519MLKEM768: true}).Parse()
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
	if err != nil || legacy == nil || legacy.ClientVersion != nil || legacy.Mldsa65Verify != nil || legacy.SupportX25519MLKEM768 {
		t.Fatalf("legacy defaults changed: config=%+v error=%v", legacy, err)
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
