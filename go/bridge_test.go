package fareward

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The vector pinned by src/bridge/auth.rs: both sides must sign the same bytes the same way.
func TestBridgeServiceAuthHeaderMatchesTheRustVector(t *testing.T) {
	ConfigureBridge("127.0.0.1:14012", "K1OzWIN0yarCc9ge")
	t.Cleanup(func() { ConfigureBridge("", "") })

	if header := makeBridgeServiceAuthHeader(1_700_000_000); header != "1700000000.7fde5fb0aac81f6e" {
		t.Fatalf("header = %q", header)
	}
}

func TestConfigureBridgeSuppliesTheScheme(t *testing.T) {
	t.Cleanup(func() { ConfigureBridge("", "") })
	for configuredURL, expectedBaseURL := range map[string]string{
		"genix-bridge.example.com/":     "https://genix-bridge.example.com",
		"127.0.0.1:14012":               "http://127.0.0.1:14012",
		"localhost:14012":               "http://localhost:14012",
		"http://10.0.0.5:14012":         "http://10.0.0.5:14012",
		" https://bridge.example.com/ ": "https://bridge.example.com",
	} {
		ConfigureBridge(configuredURL, "secret")
		if bridgeSettings.baseURL != expectedBaseURL {
			t.Errorf("%q → %q, want %q", configuredURL, bridgeSettings.baseURL, expectedBaseURL)
		}
	}
}

func TestAnUnconfiguredBridgeRefusesEveryCall(t *testing.T) {
	ConfigureBridge("", "")
	if _, err := BridgePublishTopic(context.Background(), "dining.7.3", map[string]any{}); !errors.Is(err, ErrBridgeNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}

func TestBridgePublishTopicPostsASignedRequest(t *testing.T) {
	var receivedPath, receivedAuth string
	var receivedBody map[string]any
	bridgeServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedPath = request.URL.Path
		receivedAuth = request.Header.Get(bridgeServiceAuthHeaderName)
		body, _ := io.ReadAll(request.Body)
		_ = json.Unmarshal(body, &receivedBody)
		_, _ = writer.Write([]byte(`{"Delivered":2}`))
	}))
	defer bridgeServer.Close()
	ConfigureBridge(bridgeServer.URL, "secret")
	t.Cleanup(func() { ConfigureBridge("", "") })

	deliveredCount, err := BridgePublishTopic(context.Background(), "dining.7.3", map[string]any{"Type": "dining"})
	if err != nil || deliveredCount != 2 {
		t.Fatalf("deliveredCount = %d, err = %v", deliveredCount, err)
	}
	if receivedPath != "/publish-topic" || len(receivedAuth) != len("1700000000.")+16 {
		t.Fatalf("path = %q, auth = %q", receivedPath, receivedAuth)
	}
	if receivedBody["Topic"] != "dining.7.3" || receivedBody["Message"].(map[string]any)["Type"] != "dining" {
		t.Fatalf("body = %v", receivedBody)
	}
}

func TestABridgeErrorCarriesItsMessage(t *testing.T) {
	bridgeServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusConflict)
		_, _ = writer.Write([]byte(`{"Error":"no hay ningún cliente conectado para ese tab"}`))
	}))
	defer bridgeServer.Close()
	ConfigureBridge(bridgeServer.URL, "secret")
	t.Cleanup(func() { ConfigureBridge("", "") })

	_, err := BridgeRPC(context.Background(), "Byo3bFBobzE", 9, json.RawMessage(`{"ID":9}`), 0, 0)
	if err == nil || err.Error() != "el bridge respondió 409: no hay ningún cliente conectado para ese tab" {
		t.Fatalf("err = %v", err)
	}
}
