package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecPythonSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/control/exec-python" {
			http.Error(writer, request.URL.Path, http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if body["script"] != "print(1)" || body["timeout_ms"] != float64(5000) {
			http.Error(writer, "unexpected body", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"success": true, "session_id": "s1", "session_instance_id": "i1",
			"pid": 42, "stdout": "1\n",
			"result": map[string]any{"ok": true},
			"execution_ms": 0.5, "timed_out": false, "error": "", "traceback": "",
		})
	}))
	defer server.Close()
	result, err := New(server.URL+"/control", "secret").ExecPython(context.Background(), "print(1)", nil, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.TimedOut || result.Stdout != "1\n" {
		t.Fatalf("result=%+v", result)
	}
	value, err := result.ResultValue()
	if err != nil || value == nil {
		t.Fatalf("result value err=%v value=%v", err, value)
	}
	if object := value.(map[string]any); object["ok"] != true {
		t.Fatalf("unexpected result value: %v", value)
	}
}

func TestExecPythonTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusRequestTimeout)
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"success": false, "session_id": "s1", "session_instance_id": "i1",
			"pid": 42, "stdout": "", "execution_ms": 1000.0,
			"timed_out": true, "error": "exec timeout", "traceback": "",
		})
	}))
	defer server.Close()
	result, err := New(server.URL+"/control", "secret").ExecPython(context.Background(), "time.sleep(9)", nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.Error != "exec timeout" {
		t.Fatalf("result=%+v", result)
	}
}

func TestExecPythonScriptError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"success": false, "session_id": "s1", "session_instance_id": "i1",
			"pid": 42, "stdout": "", "execution_ms": 0.3,
			"timed_out": false, "error": "ValueError: boom", "traceback": "Traceback...",
		})
	}))
	defer server.Close()
	result, err := New(server.URL+"/control", "secret").ExecPython(context.Background(), "raise ValueError('boom')", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.Success || result.Error != "ValueError: boom" {
		t.Fatalf("result=%+v", result)
	}
}
