package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmo/dscida/internal/store"
)

func TestVerifyControlIdentityAcceptsBinaryTaggedUnion(t *testing.T) {
	session := &store.Session{
		SchemaVersion: store.SessionSchemaVersion, SessionID: "binary",
		SessionInstanceID: "instance-0123456789abcdef", TargetKind: store.TargetBinary,
		State: "ready", IDAPID: os.Getpid(), ControlToken: "secret",
		SourcePath: "/source/input", InputPath: "/session/inputs/input",
		InputSHA256: strings.Repeat("a", 64), InputSize: 123, BinaryFormat: "elf",
		Architecture: "em_x86_64", IDAProcessor: "pc",
		WorkingIDBPath: filepath.Join(t.TempDir(), "working.i64"),
	}
	reportedSHA := session.InputSHA256
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		output.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/control/ping" {
			_ = json.NewEncoder(output).Encode(map[string]any{"success": true, "pid": session.IDAPID})
			return
		}
		_ = json.NewEncoder(output).Encode(map[string]any{
			"success": true, "schema_version": 2, "session_id": session.SessionID,
			"session_instance_id": session.SessionInstanceID, "pid": session.IDAPID,
			"target_kind": store.TargetBinary, "source_path": session.SourcePath,
			"input_path": session.InputPath, "input_sha256": reportedSHA,
			"input_size": session.InputSize, "binary_format": session.BinaryFormat,
			"architecture": session.Architecture, "ida_processor": session.IDAProcessor,
			"macho_uuid": "",
			"ida":        map[string]any{"idb_path": session.WorkingIDBPath},
		})
	}))
	defer server.Close()
	session.ControlURL = server.URL + "/control"
	session.MCPURL = server.URL + "/mcp"
	if err := verifyControlIdentity(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	session.InputSHA256 = strings.Repeat("b", 64)
	if err := verifyControlIdentity(context.Background(), session); err == nil {
		t.Fatal("mismatched binary identity unexpectedly accepted")
	}
}
