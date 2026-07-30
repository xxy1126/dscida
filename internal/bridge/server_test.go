package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmo/dscida/internal/store"
)

func TestBridgePublishesToolsForwardsAndRejectsReplacement(t *testing.T) {
	st, session := bridgeTestSession(t)
	var toolCalls atomic.Int64
	var blockControl atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/control/ping":
			if blockControl.Load() {
				<-request.Context().Done()
				return
			}
			writeTestJSON(output, map[string]any{"success": true, "pid": os.Getpid()})
		case "/control/status":
			writeTestJSON(output, map[string]any{
				"success": true, "schema_version": 2,
				"session_id":          session.SessionID,
				"session_instance_id": session.SessionInstanceID,
				"pid":                 os.Getpid(), "target_kind": store.TargetDSC, "dsc_path": session.DSCPath,
				"dsc_uuid": session.DSCUUID, "main_module": session.MainModule,
				"ida": map[string]any{"idb_path": session.WorkingIDBPath},
			})
		case "/mcp":
			if request.Method == http.MethodDelete {
				output.WriteHeader(http.StatusOK)
				return
			}
			if request.Method == http.MethodGet {
				output.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var message struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
				t.Errorf("decode mock MCP: %v", err)
				output.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(message.ID) == 0 {
				output.WriteHeader(http.StatusAccepted)
				return
			}
			output.Header().Set("Mcp-Session-Id", "mock-session")
			switch message.Method {
			case "initialize":
				writeRPCResult(output, message.ID, map[string]any{
					"protocolVersion": protocolVersion,
					"capabilities": map[string]any{
						"tools": map[string]any{"listChanged": true},
					},
					"serverInfo": map[string]any{"name": "mock", "version": "1"},
				})
			case "tools/list":
				writeRPCResult(output, message.ID, map[string]any{
					"tools": []map[string]any{
						{"name": "server_health", "description": "health", "inputSchema": map[string]any{"type": "object"}},
						{"name": "identity", "description": "identity", "inputSchema": map[string]any{"type": "object"}},
					},
				})
			case "tools/call":
				if message.Params.Name == "server_health" {
					writeRPCResult(output, message.ID, map[string]any{
						"structuredContent": map[string]any{
							"status": "ok", "idb_path": session.WorkingIDBPath,
							"input_path": session.DSCPath, "auto_analysis_ready": true,
						},
					})
					return
				}
				toolCalls.Add(1)
				writeRPCResult(output, message.ID, map[string]any{
					"structuredContent": map[string]any{"session": session.SessionID},
				})
			default:
				t.Errorf("unexpected downstream method %s", message.Method)
			}
		default:
			http.NotFound(output, request)
		}
	}))
	defer server.Close()
	session.State = "ready"
	session.IDAPID = os.Getpid()
	session.ControlURL = server.URL + "/control"
	session.MCPURL = server.URL + "/mcp"
	if err := st.SaveSession(session); err != nil {
		t.Fatal(err)
	}

	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	service, err := New(Config{
		Store: st, SessionID: session.SessionID, ServerName: "dscida_test",
		PollInterval: 10 * time.Millisecond, Input: inputReader, Output: outputWriter,
	})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- service.Run(context.Background())
		outputWriter.Close()
	}()
	messages := make(chan map[string]any, 32)
	go func() {
		scanner := bufio.NewScanner(outputReader)
		for scanner.Scan() {
			var message map[string]any
			if json.Unmarshal(scanner.Bytes(), &message) == nil {
				messages <- message
			}
		}
		close(messages)
	}()
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-11-25"},
	})
	initialize := awaitResponse(t, messages, 1)
	result := initialize["result"].(map[string]any)
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("negotiated protocol=%v", result["protocolVersion"])
	}
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{},
	})

	var listed map[string]any
	for id := 2; id < 30; id++ {
		sendUpstream(t, inputWriter, map[string]any{
			"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": map[string]any{},
		})
		listed = awaitResponse(t, messages, id)
		tools := listed["result"].(map[string]any)["tools"].([]any)
		if len(tools) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(listed["result"].(map[string]any)["tools"].([]any)); got != 2 {
		t.Fatalf("published tools=%d, want 2", got)
	}
	blockControl.Store(true)
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "id": 29, "method": "tools/call",
		"params": map[string]any{"name": "identity", "arguments": map[string]any{}},
	})
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": 29, "reason": "test cancellation"},
	})
	cancelled := awaitResponse(t, messages, 29)
	blockControl.Store(false)
	if cancelled["error"].(map[string]any)["code"] != float64(-32800) ||
		toolCalls.Load() != 0 {
		t.Fatalf("cancelled response=%v count=%d", cancelled, toolCalls.Load())
	}
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "id": 30, "method": "tools/call",
		"params": map[string]any{"name": "identity", "arguments": map[string]any{}},
	})
	call := awaitResponse(t, messages, 30)
	if call["error"] != nil || toolCalls.Load() != 1 {
		t.Fatalf("tool call=%v count=%d", call, toolCalls.Load())
	}

	session.SessionInstanceID = "instance-replaced"
	if err := store.WriteJSON(
		filepath.Join(st.SessionDir(session.SessionID), "session.json"), session, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	sendUpstream(t, inputWriter, map[string]any{
		"jsonrpc": "2.0", "id": 31, "method": "tools/call",
		"params": map[string]any{"name": "identity", "arguments": map[string]any{}},
	})
	replaced := awaitResponse(t, messages, 31)
	rpcError := replaced["error"].(map[string]any)
	if rpcError["code"] != float64(-32064) || toolCalls.Load() != 1 {
		t.Fatalf("replacement response=%v count=%d", replaced, toolCalls.Load())
	}
	inputWriter.Close()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not stop after stdin closed")
	}
}

func bridgeTestSession(t *testing.T) (*store.Store, *store.Session) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := &store.Session{
		SessionID: "test", State: "creating", ControlToken: "token",
		DSCPath: "/firmware/dyld_shared_cache_arm64e", DSCUUID: "UUID",
		MainModule: "/System/Library/Frameworks/Security.framework/Security",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	session.WorkingIDBPath = filepath.Join(st.SessionDir(session.SessionID), "runtime", "working.i64")
	return st, session
}

func sendUpstream(t *testing.T, output io.Writer, message any) {
	t.Helper()
	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	if _, err := output.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func awaitResponse(t *testing.T, messages <-chan map[string]any, id int) map[string]any {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case message, ok := <-messages:
			if !ok {
				t.Fatal("bridge output closed")
			}
			if message["id"] == float64(id) {
				return message
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for response %d", id)
		}
	}
}

func writeRPCResult(output http.ResponseWriter, id json.RawMessage, result any) {
	writeTestJSON(output, map[string]any{
		"jsonrpc": "2.0", "id": json.RawMessage(bytes.Clone(id)), "result": result,
	})
}

func writeTestJSON(output http.ResponseWriter, value any) {
	output.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(output).Encode(value); err != nil {
		panic(fmt.Sprintf("encode mock response: %v", err))
	}
}
