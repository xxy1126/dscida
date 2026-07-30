package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/control/status" {
			http.Error(writer, request.URL.Path, http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(writer).Encode(map[string]bool{"success": true})
	}))
	defer server.Close()
	var result map[string]bool
	if err := New(server.URL+"/control", "secret").Get(context.Background(), "/control/status", &result); err != nil {
		t.Fatal(err)
	}
	if !result["success"] {
		t.Fatalf("result=%v", result)
	}
}

func TestMCPHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var envelope struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch envelope.Method {
		case "initialize":
			writer.Header().Set("Mcp-Session-Id", "test-session")
			json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1, "result": map[string]any{"protocolVersion": "2025-06-18"},
			})
		case "tools/list":
			if request.Header.Get("Mcp-Session-Id") != "test-session" {
				http.Error(writer, "missing session", http.StatusBadRequest)
				return
			}
			json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 2,
				"result": map[string]any{"tools": []map[string]string{{"name": "server_health"}}},
			})
		case "tools/call":
			json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 2,
				"result": map[string]any{
					"structuredContent": map[string]any{
						"status": "ok", "idb_path": "/tmp/test.i64",
						"input_path": "/tmp/cache", "auto_analysis_ready": true,
						"hexrays_ready": true,
					},
					"isError": false,
				},
			})
		default:
			http.Error(writer, "unknown method", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	if err := MCPHealth(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	health, err := MCPServerHealth(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !health.AutoAnalysisReady || health.IDBPath != "/tmp/test.i64" {
		t.Fatalf("health=%+v", health)
	}
}
