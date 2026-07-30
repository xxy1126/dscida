package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionlessDownstreamProtocolHeaderAndCancellation(t *testing.T) {
	callStarted := make(chan uint64, 1)
	cancelled := make(chan uint64, 1)
	server := httptest.NewServer(http.HandlerFunc(func(
		output http.ResponseWriter, request *http.Request,
	) {
		if request.Method == http.MethodGet {
			output.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var message struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				RequestID uint64 `json:"requestId"`
			} `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Errorf("decode request: %v", err)
			output.WriteHeader(http.StatusBadRequest)
			return
		}
		switch message.Method {
		case "initialize":
			writeRPCResult(output, json.RawMessage("1"), map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "sessionless", "version": "1"},
			})
		case "notifications/initialized":
			if request.Header.Get("MCP-Protocol-Version") != protocolVersion {
				t.Errorf("initialized protocol header=%q", request.Header.Get("MCP-Protocol-Version"))
			}
			output.WriteHeader(http.StatusAccepted)
		case "tools/call":
			if request.Header.Get("MCP-Protocol-Version") != protocolVersion {
				t.Errorf("call protocol header=%q", request.Header.Get("MCP-Protocol-Version"))
			}
			callStarted <- message.ID
			<-request.Context().Done()
		case "notifications/cancelled":
			cancelled <- message.Params.RequestID
			output.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected method %q", message.Method)
			output.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	item, err := newDownstream(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer item.close()
	if item.client.Timeout != 0 {
		t.Fatalf("downstream client has global timeout %s", item.client.Timeout)
	}
	callContext, cancel := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() {
		_, _, callErr := item.call(callContext, "tools/call", map[string]any{
			"name": "slow", "arguments": map[string]any{},
		})
		callDone <- callErr
	}()
	var requestID uint64
	select {
	case requestID = <-callStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("downstream call did not start")
	}
	cancel()
	select {
	case got := <-cancelled:
		if got != requestID {
			t.Fatalf("cancelled request ID=%d, want %d", got, requestID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("downstream cancellation notification not received")
	}
	select {
	case err := <-callDone:
		if err == nil {
			t.Fatal("cancelled downstream call returned no error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled downstream call did not finish")
	}
}

func TestDownstreamClientDoesNotFollowRedirects(t *testing.T) {
	var targetCalled bool
	target := httptest.NewServer(http.HandlerFunc(func(
		output http.ResponseWriter, request *http.Request,
	) {
		targetCalled = true
		output.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(
		output http.ResponseWriter, request *http.Request,
	) {
		http.Redirect(output, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	response, err := noRedirectHTTPClient().Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || targetCalled {
		t.Fatalf("status=%d target_called=%t", response.StatusCode, targetCalled)
	}
}
