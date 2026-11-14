package fareward

// Client of the SSE bridge's service half (../README.md, "SSE bridge HTTP contract"). The bridge
// is an HTTP process, unlike the raw-TCP limiter in connection.go, and shares only the secret with
// it: every call carries X-Bridge-Auth, a timestamp signed with the same internal API key under
// its own domain string.
//
//	BridgePublish      → POST /publish        one event down one tab's stream
//	BridgeRPC          → POST /rpc            a command, blocking until the tab answers
//	BridgePublishTopic → POST /publish-topic  one event to every tab subscribed to a topic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanjoz/fareward/go/siphash"
)

const (
	// bridgeServiceAuthHeaderName and bridgeServiceAuthMessagePrefix mirror
	// src/bridge/auth.rs. The bridge is a Rust process, so the compiler cannot enforce this —
	// changing one side requires changing the other.
	bridgeServiceAuthHeaderName    = "X-Bridge-Auth"
	bridgeServiceAuthMessagePrefix = "sse-bridge:v2|"
)

// ErrBridgeNotConfigured is returned by every call made with no bridge URL configured.
var ErrBridgeNotConfigured = errors.New("fareward: the SSE bridge URL is not configured")

// bridgeSettings is written once at startup by ConfigureBridge and only read afterwards.
var bridgeSettings struct {
	baseURL string
	signKey siphash.Key
}

// bridgeHTTPClient has no client-level timeout on purpose: /rpc blocks until the browser
// answers, and the caller's context is what bounds every call.
var bridgeHTTPClient = &http.Client{}

// ConfigureBridge installs the bridge's base URL and the internal API key that signs the calls.
// An empty URL leaves the bridge unconfigured, which is a valid deployment (BridgeConfigured).
//
// A bare host gets a scheme here: the deploy script only wants the hostname (it names the
// proxy site), so a scheme-less value passes configuration unnoticed and would otherwise fail
// every call with "unsupported protocol scheme", far from the edit that caused it. Loopback means
// a bridge started by hand for a local test, with no proxy terminating TLS.
func ConfigureBridge(bridgeURL, internalAPIKey string) {
	baseURL := strings.TrimRight(strings.TrimSpace(bridgeURL), "/")
	if len(baseURL) > 0 && !strings.Contains(baseURL, "://") {
		if strings.HasPrefix(baseURL, "127.0.0.1") || strings.HasPrefix(baseURL, "localhost") {
			baseURL = "http://" + baseURL
		} else {
			baseURL = "https://" + baseURL
		}
	}
	bridgeSettings.baseURL = baseURL
	bridgeSettings.signKey = siphash.DeriveKey([]byte(internalAPIKey))
}

// BridgeConfigured reports whether ConfigureBridge was given a URL.
func BridgeConfigured() bool { return len(bridgeSettings.baseURL) > 0 }

// makeBridgeServiceAuthHeader signs the current timestamp. SipHash-2-4, like the TCP frame tag:
// 16 hex characters. %016x, not FormatUint: a tag whose top nibble is zero must still be 16
// characters, or the bridge's fixed-width comparison rejects it.
func makeBridgeServiceAuthHeader(unixSeconds int64) string {
	timestampText := strconv.FormatInt(unixSeconds, 10)
	hasher := siphash.New(bridgeSettings.signKey)
	hasher.WriteString(bridgeServiceAuthMessagePrefix + timestampText)
	return timestampText + "." + fmt.Sprintf("%016x", hasher.Sum64())
}

// bridgeCall posts one authenticated request and decodes the JSON answer into responseTarget.
func bridgeCall(ctx context.Context, path string, requestBody any, responseTarget any) error {
	if !BridgeConfigured() {
		return ErrBridgeNotConfigured
	}
	encodedBody, marshalError := json.Marshal(requestBody)
	if marshalError != nil {
		return fmt.Errorf("serializar la petición al bridge: %w", marshalError)
	}
	bridgeRequest, requestError := http.NewRequestWithContext(
		ctx, http.MethodPost, bridgeSettings.baseURL+path, bytes.NewReader(encodedBody))
	if requestError != nil {
		return fmt.Errorf("construir la petición al bridge: %w", requestError)
	}
	bridgeRequest.Header.Set("Content-Type", "application/json")
	bridgeRequest.Header.Set(bridgeServiceAuthHeaderName, makeBridgeServiceAuthHeader(time.Now().Unix()))

	bridgeResponse, callError := bridgeHTTPClient.Do(bridgeRequest)
	if callError != nil {
		return fmt.Errorf("el bridge no respondió: %w", callError)
	}
	defer bridgeResponse.Body.Close()

	responseBody, readError := io.ReadAll(bridgeResponse.Body)
	if readError != nil {
		return fmt.Errorf("leer la respuesta del bridge: %w", readError)
	}
	if bridgeResponse.StatusCode != http.StatusOK {
		errorDetail := struct{ Error string }{}
		_ = json.Unmarshal(responseBody, &errorDetail)
		if len(errorDetail.Error) == 0 {
			errorDetail.Error = string(responseBody[:min(len(responseBody), 200)])
		}
		return fmt.Errorf("el bridge respondió %d: %s", bridgeResponse.StatusCode, errorDetail.Error)
	}
	return json.Unmarshal(responseBody, responseTarget)
}

// BridgePublish pushes one message to a tab's stream. waitMs lets the bridge hold it for a tab
// that is reconnecting. A tab with no stream is not an error: delivered comes back false, since
// the bridge buffers nothing by design.
func BridgePublish(ctx context.Context, channelToken string, message json.RawMessage, waitMs int) (delivered bool, err error) {
	publishResponse := struct{ Delivered bool }{}
	err = bridgeCall(ctx, "/publish", map[string]any{
		"Channel": channelToken, "Message": message, "WaitMs": waitMs,
	}, &publishResponse)
	return publishResponse.Delivered, err
}

// BridgeRPCReply is the tab's answer to a command: Kind "result" or "error".
type BridgeRPCReply struct {
	Kind    string
	Payload json.RawMessage
}

// BridgeRPC pushes a command and blocks until the tab answers it. commandID must match the id
// inside message: the browser echoes it back and that is what the bridge correlates. timeoutMs 0
// takes the bridge's default.
func BridgeRPC(ctx context.Context, channelToken string, commandID uint64, message json.RawMessage, timeoutMs, waitMs int) (BridgeRPCReply, error) {
	reply := BridgeRPCReply{}
	err := bridgeCall(ctx, "/rpc", map[string]any{
		"Channel": channelToken, "ID": commandID, "Message": message,
		"TimeoutMs": timeoutMs, "WaitMs": waitMs,
	}, &reply)
	return reply, err
}

// BridgePublishTopic fans one message out to every tab subscribed to topic
// (`<name>.<companyID>[.<more>]`) and returns how many tabs queued it. It never waits for a tab:
// topic messages are nudges a page can always recover from through the normal API.
func BridgePublishTopic(ctx context.Context, topic string, message any) (deliveredCount int, err error) {
	publishResponse := struct{ Delivered int }{}
	err = bridgeCall(ctx, "/publish-topic", map[string]any{"Topic": topic, "Message": message}, &publishResponse)
	return publishResponse.Delivered, err
}
