package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testDSCSession(id, state string) *Session {
	return &Session{
		SessionID: id, TargetKind: TargetDSC, State: state, ControlToken: "secret",
		DSCPath: "/cache", DSCUUID: "UUID", MainModule: "/module",
	}
}

func TestWriteJSONReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := WriteJSON(path, map[string]int{"value": 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, map[string]int{"value": 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	var got map[string]int
	if err := ReadJSON(path, &got); err != nil {
		t.Fatal(err)
	}
	if got["value"] != 2 {
		t.Fatalf("got %v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestNewMakesStateAndSessionsPrivate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sessions"), 0o777); err != nil {
		t.Fatal(err)
	}
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{st.Root, filepath.Join(st.Root, "sessions")} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode=%v", path, info.Mode())
		}
	}
}

func TestNewRejectsSymlinkedSessionsRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	outside := t.TempDir()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sessions")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); err == nil {
		t.Fatal("symlinked sessions root unexpectedly accepted")
	}
}

func TestInitializeCreatesSchemaV2SessionInstanceIdentity(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := testDSCSession("identity", "creating")
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	if session.SchemaVersion != SessionSchemaVersion ||
		!ValidID(session.SessionInstanceID) {
		t.Fatalf(
			"schema=%d instance=%q",
			session.SchemaVersion, session.SessionInstanceID,
		)
	}
	reloaded, err := st.LoadSession(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SessionInstanceID != session.SessionInstanceID {
		t.Fatalf(
			"reloaded instance=%q, want %q",
			reloaded.SessionInstanceID, session.SessionInstanceID,
		)
	}
}

func TestSaveSessionRejectsInstanceIdentityChange(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := testDSCSession("immutable", "creating")
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	session.SessionInstanceID = "instance-replaced"
	if err := st.SaveSession(session); err == nil {
		t.Fatal("changed session instance identity unexpectedly saved")
	}
}

func TestValidateEndpointPairRequiresSameLoopbackListener(t *testing.T) {
	if err := ValidateEndpointPair(
		"http://127.0.0.1:1234/control",
		"http://127.0.0.1:1234/mcp",
	); err != nil {
		t.Fatal(err)
	}
	for _, mcpURL := range []string{
		"http://127.0.0.1:4321/mcp",
		"http://example.com:1234/mcp",
		"http://127.0.0.1:1234/other",
	} {
		if err := ValidateEndpointPair(
			"http://127.0.0.1:1234/control", mcpURL,
		); err == nil {
			t.Fatalf("invalid endpoint pair accepted: %s", mcpURL)
		}
	}
}

func TestClearHistoricalJobDoesNotChangeSessionState(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := testDSCSession("historical", "stopped")
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearActiveJob(session, "job-deadbeefdeadbeef", "ready"); err != nil {
		t.Fatal(err)
	}
	fresh, err := st.LoadSession("historical")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != "stopped" {
		t.Fatalf("historical clear changed state to %s", fresh.State)
	}
}

func TestLifecycleLockSerializesCallers(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	unlockFirst, err := st.LockLifecycle("locked")
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		unlock, lockErr := st.LockLifecycle("locked")
		if lockErr == nil {
			acquired <- unlock
		}
	}()
	select {
	case unlock := <-acquired:
		unlock()
		t.Fatal("second lifecycle owner acquired before first released")
	case <-time.After(50 * time.Millisecond):
	}
	unlockFirst()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("second lifecycle owner did not acquire after release")
	}
}

func TestNewJobMakesSessionBusy(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := testDSCSession("test", "ready")
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	index := 29
	job, err := st.NewJob(session, "add", "/Security", &index)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.ActiveJobIDs) != 1 || session.ActiveJobIDs[0] != job.JobID {
		t.Fatalf("active jobs=%v", session.ActiveJobIDs)
	}
	if _, err := st.NewJob(session, "save", "", nil); err == nil {
		t.Fatal("second mutating job unexpectedly accepted")
	}
}

func TestConcurrentNewJobHasSingleWinner(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := testDSCSession("concurrent", "ready")
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	const count = 8
	results := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			fresh, loadErr := st.LoadSession("concurrent")
			if loadErr != nil {
				results <- loadErr
				return
			}
			_, createErr := st.NewJob(fresh, "save", "", nil)
			results <- createErr
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent writers=%d, want 1", successes)
	}
}

func TestLoadCurrentDetectsTampering(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{
		SessionID: "verify", State: "ready", ControlToken: "secret",
		DSCPath: "/cache", DSCUUID: "UUID", MainModule: "/module",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	generation := filepath.Join(st.SessionDir("verify"), "generations", "000001.i64")
	if err := os.WriteFile(generation, []byte("valid"), 0o400); err != nil {
		t.Fatal(err)
	}
	sum, err := SHA256File(generation)
	if err != nil {
		t.Fatal(err)
	}
	current := &Current{
		SchemaVersion: SchemaVersion, Generation: 1, Path: generation, SHA256: sum,
		DSCPath: session.DSCPath, DSCUUID: session.DSCUUID, MainModule: session.MainModule,
	}
	if err := WriteJSON(filepath.Join(st.SessionDir("verify"), "current.json"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err != nil {
		t.Fatalf("valid current rejected: %v", err)
	}
	if err := os.Chmod(generation, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(generation, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err == nil {
		t.Fatal("tampered generation unexpectedly accepted")
	}
}

func TestBinaryCurrentRequiresCompleteTaggedIdentity(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionDir := st.SessionDir("binary-current")
	inputPath := filepath.Join(sessionDir, "inputs", strings.Repeat("a", 64)+"__input")
	session := &Session{
		SessionID: "binary-current", TargetKind: TargetBinary, State: "ready",
		ControlToken: "secret", SourcePath: "/source/input", InputPath: inputPath,
		InputSHA256: strings.Repeat("a", 64), InputSize: 4,
		BinaryFormat: "elf", Architecture: "em_x86_64", IDAProcessor: "pc",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, []byte("ELF!"), 0o400); err != nil {
		t.Fatal(err)
	}
	generation := filepath.Join(sessionDir, "generations", "000001.i64")
	if err := os.WriteFile(generation, []byte("idb"), 0o400); err != nil {
		t.Fatal(err)
	}
	sum, err := SHA256File(generation)
	if err != nil {
		t.Fatal(err)
	}
	current := &Current{
		SchemaVersion: CurrentSchemaVersion, Generation: 1, Path: generation,
		SHA256: sum, TargetKind: TargetBinary, SourcePath: session.SourcePath,
		InputPath: session.InputPath, InputSHA256: session.InputSHA256,
		InputSize: session.InputSize, BinaryFormat: session.BinaryFormat,
		Architecture: session.Architecture, IDAProcessor: session.IDAProcessor,
	}
	if err := WriteJSON(filepath.Join(sessionDir, "current.json"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err != nil {
		t.Fatalf("valid binary current rejected: %v", err)
	}
	current.SourcePath = "/different/source"
	if err := WriteJSON(filepath.Join(sessionDir, "current.json"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err == nil {
		t.Fatal("mismatched binary current source unexpectedly accepted")
	}
	current.SourcePath = session.SourcePath
	current.SchemaVersion = SchemaVersion
	if err := WriteJSON(filepath.Join(sessionDir, "current.json"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err == nil {
		t.Fatal("legacy current schema unexpectedly accepted for binary target")
	}
}

func TestWithinCanonicalizesSymlinkedAncestors(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real", "session")
	if err := os.MkdirAll(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "real"), alias); err != nil {
		t.Fatal(err)
	}
	if !within(filepath.Join(alias, "session"), filepath.Join(realParent, "staging", "new.i64")) {
		t.Fatal("equivalent paths through a symlinked ancestor were rejected")
	}
	if within(filepath.Join(alias, "session"), filepath.Join(root, "outside.i64")) {
		t.Fatal("path outside the canonical parent was accepted")
	}
	if !SamePath(filepath.Join(alias, "session"), realParent) {
		t.Fatal("canonical path equality rejected equivalent paths")
	}
}

func TestLoadCurrentRejectsNonGenerationPath(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{
		SessionID: "wrong-current", State: "ready", ControlToken: "secret",
		DSCPath: "/cache", DSCUUID: "UUID", MainModule: "/module",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(st.SessionDir(session.SessionID), "runtime", "working.i64")
	if err := os.WriteFile(runtime, []byte("not committed"), 0o400); err != nil {
		t.Fatal(err)
	}
	sum, err := SHA256File(runtime)
	if err != nil {
		t.Fatal(err)
	}
	current := &Current{
		SchemaVersion: SchemaVersion, Generation: 1, Path: runtime, SHA256: sum,
		DSCPath: session.DSCPath, DSCUUID: session.DSCUUID, MainModule: session.MainModule,
	}
	if err := WriteJSON(filepath.Join(st.SessionDir(session.SessionID), "current.json"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCurrent(session); err == nil {
		t.Fatal("runtime IDB was accepted as a committed generation")
	}
}

func TestValidateEndpointRejectsAmbiguousURLs(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1/control",
		"http://127.0.0.1:1234/control?redirect=/mcp",
		"http://127.0.0.1:1234/control#fragment",
		"http://example.com:1234/control",
	} {
		if err := validateEndpoint(endpoint, "/control"); err == nil {
			t.Fatalf("accepted invalid endpoint %q", endpoint)
		}
	}
	if err := validateEndpoint("http://127.0.0.1:1234/control", "/control"); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
}
