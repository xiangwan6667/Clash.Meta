package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mldsa"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	ShortID       string `proxy:"short-id,omitempty"`
	ClientVersion string `proxy:"client-version,omitempty"`
	Mldsa65Verify string `proxy:"mldsa65-verify,omitempty"`

	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}
		if o.Mldsa65Verify != "" {
			if len(o.Mldsa65Verify) != base64.RawURLEncoding.EncodedLen(mldsa.MLDSA65PublicKeySize) {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
			verifyKey, err := base64.RawURLEncoding.DecodeString(o.Mldsa65Verify)
			if err != nil {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
			config.Mldsa65Verify, err = mldsa.NewPublicKey(mldsa.MLDSA65(), verifyKey)
			if err != nil {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
		}
		if o.ClientVersion != "" {
			parts := strings.Split(o.ClientVersion, ".")
			if len(parts) != 3 {
				return nil, errors.New("invalid REALITY client version: expected x.y.z")
			}
			version := new([3]byte)
			for i, part := range parts {
				value, err := strconv.ParseUint(part, 10, 8)
				if err != nil {
					return nil, errors.New("invalid REALITY client version: components must be between 0 and 255")
				}
				version[i] = byte(value)
			}
			config.ClientVersion = version
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	if o.Mldsa65Verify != "" {
		return nil, errors.New("REALITY ML-DSA-65 verification requires a public key")
	}
	if o.ClientVersion != "" {
		return nil, errors.New("REALITY client version requires a public key")
	}
	return nil, nil
}
