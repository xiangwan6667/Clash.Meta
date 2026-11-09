package convert_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mldsa"
	"github.com/stretchr/testify/require"
)

func TestConvertsRealityVerificationKey(t *testing.T) {
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	require.NoError(t, err)
	pqv := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	for _, scheme := range []string{"vless", "vmess"} {
		t.Run(scheme, func(t *testing.T) {
			link := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=" + publicKey + "&pqv=" + pqv
			for _, input := range []string{link, base64.StdEncoding.EncodeToString([]byte(link))} {
				proxies, err := convert.ConvertsV2Ray([]byte(input))
				require.NoError(t, err)
				require.Len(t, proxies, 1)
				require.Equal(t, pqv, proxies[0]["reality-opts"].(map[string]any)["mldsa65-verify"])
				_, err = adapter.ParseProxy(proxies[0])
				require.NoError(t, err)
			}

			invalidKey := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=" + publicKey + "&pqv=x"
			proxies, err := convert.ConvertsV2Ray([]byte(invalidKey))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			_, err = adapter.ParseProxy(proxies[0])
			require.Error(t, err, "invalid verification keys must not be silently ignored")

			missingKey := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pqv=x"
			proxies, _ = convert.ConvertsV2Ray([]byte(missingKey))
			require.Empty(t, proxies, "a verification key must never be silently discarded")
		})
	}
}

func TestConvertsRealityXHTTPDownloadSettings(t *testing.T) {
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	require.NoError(t, err)
	pqv := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	downloadKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for _, tt := range []struct {
		name       string
		serverName string
		publicKey  string
		wantKey    string
	}{
		{name: "password and explicit server name", serverName: "download.example.test", wantKey: downloadKey},
		{name: "omitted server name preserves inheritance", wantKey: downloadKey},
		{name: "existing public key precedence", publicKey: publicKey, wantKey: publicKey},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			realitySettings := map[string]any{
				"password": downloadKey, "shortId": "0123",
				"mldsa65Verify": pqv, "fingerprint": "firefox",
			}
			if tt.publicKey != "" {
				realitySettings["publicKey"] = tt.publicKey
			}
			if tt.serverName != "" {
				realitySettings["serverName"] = tt.serverName
			}
			extra, err := json.Marshal(map[string]any{"downloadSettings": map[string]any{
				"address": "download.example.test", "port": 443,
				"network": "xhttp", "security": "reality", "realitySettings": realitySettings,
				"xhttpSettings": map[string]any{"path": "/down"},
			}})
			require.NoError(t, err)
			link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&type=xhttp&mode=stream-up&sni=upload.example.test&fp=chrome&pbk=" + publicKey + "&extra=" + url.QueryEscape(string(extra))
			proxies, err := convert.ConvertsV2Ray([]byte(link))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			opts := proxies[0]["xhttp-opts"].(map[string]any)
			download := opts["download-settings"].(map[string]any)
			if tt.serverName != "" {
				require.Equal(t, tt.serverName, download["servername"])
			} else {
				require.NotContains(t, download, "servername")
			}
			require.Equal(t, "firefox", download["client-fingerprint"])
			require.Equal(t, map[string]any{"public-key": tt.wantKey, "short-id": "0123", "mldsa65-verify": pqv}, download["reality-opts"])
			_, err = adapter.ParseProxy(proxies[0])
			require.NoError(t, err)
		})
	}
}
