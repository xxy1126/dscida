package app

import (
	"bytes"
	"context"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func TestCLICompatibilityFixtures(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := Run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "0.1.0\n" || stderr.Len() != 0 {
		t.Fatalf("version stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := Run([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "dscida doctor --probe-dsc") {
		t.Fatalf("help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	err := Run([]string{"not-a-command"}, io.Discard, io.Discard)
	if err == nil || err.Error() != `unknown command "not-a-command" (run dscida help)` {
		t.Fatalf("unknown command result=%v", err)
	}
}

func TestParseInterspersed(t *testing.T) {
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	query := set.String("query", "", "")
	jsonOutput := set.Bool("json", false, "")
	if err := parseInterspersed(set, []string{"/cache", "--query", "Security", "--json"}); err != nil {
		t.Fatal(err)
	}
	if set.NArg() != 1 || set.Arg(0) != "/cache" || *query != "Security" || !*jsonOutput {
		t.Fatalf("args=%v query=%q json=%t", set.Args(), *query, *jsonOutput)
	}
}

func TestExpectedIndexes(t *testing.T) {
	target := 3534
	session := &store.Session{ImageCount: 4311, LoadedImageIndexes: []int{29}}
	job := &store.Job{Operation: "add", ImageIndex: &target}
	got, err := expectedIndexes(session, job)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{29, 3534}) {
		t.Fatalf("got %v", got)
	}
}

func TestExpectedIndexesRejectsOutOfBounds(t *testing.T) {
	target := 4311
	_, err := expectedIndexes(
		&store.Session{ImageCount: 4311, LoadedImageIndexes: []int{29}},
		&store.Job{Operation: "add", ImageIndex: &target},
	)
	if err == nil {
		t.Fatal("out-of-bounds index unexpectedly accepted")
	}
}

func TestObservedIndexesAllowValidatedImplicitModules(t *testing.T) {
	got, err := validateObservedIndexes([]int{3534, 0, 29}, []int{29, 3534}, 4311)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{0, 29, 3534}) {
		t.Fatalf("got %v", got)
	}
}

func TestObservedIndexesCannotLoseCommittedModule(t *testing.T) {
	if _, err := validateObservedIndexes([]int{3534}, []int{29, 3534}, 4311); err == nil {
		t.Fatal("missing committed index unexpectedly accepted")
	}
}

func TestRecoverySkipsSessionAfterStopConsumedJob(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := &store.Session{
		SessionID: "stop-wins", State: "ready", ControlToken: "secret",
		CurrentGeneration: 1, TargetKind: store.TargetDSC,
		DSCPath: "/cache", DSCUUID: "UUID", MainModule: "/module",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	job, err := st.NewJob(session, "save", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	job.State = "cancelled_before_start"
	job.Error = "stopped"
	if err := st.SaveJob(job); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearActiveJob(session, job.JobID, "stopped"); err != nil {
		t.Fatal(err)
	}
	unlock, err := st.LockLifecycle(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	env := &environment{stdout: io.Discard, stderr: io.Discard}
	recoveryErr := env.failAndRecover(
		context.Background(), st, &runner.Runner{IDAT: "/not-used"},
		session, job, true, context.Canceled,
	)
	if recoveryErr == nil || !strings.Contains(recoveryErr.Error(), "no longer owns") {
		t.Fatalf("unexpected recovery result: %v", recoveryErr)
	}
	fresh, err := st.LoadSession(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != "stopped" || fresh.IDAPID != 0 {
		t.Fatalf("stopped session was changed: state=%s pid=%d", fresh.State, fresh.IDAPID)
	}
}

func TestRecoveryUsesCallerDeadline(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := &store.Session{
		SessionID: "deadline", State: "ready", ControlToken: "secret",
		CurrentGeneration: 1, TargetKind: store.TargetDSC,
		DSCPath: "/cache", DSCUUID: "UUID", MainModule: "/module",
	}
	if err := st.Initialize(session); err != nil {
		t.Fatal(err)
	}
	job, err := st.NewJob(session, "save", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	env := &environment{stdout: io.Discard, stderr: io.Discard}
	recoveryErr := env.failAndRecover(
		ctx, st, &runner.Runner{IDAT: "/not-used"},
		session, job, false, context.DeadlineExceeded,
	)
	if recoveryErr == nil || !strings.Contains(recoveryErr.Error(), "command deadline expired") {
		t.Fatalf("unexpected recovery result: %v", recoveryErr)
	}
	fresh, err := st.LoadSession(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != "recovery_required" || len(fresh.ActiveJobIDs) != 0 {
		t.Fatalf("deadline recovery state=%s active=%v", fresh.State, fresh.ActiveJobIDs)
	}
}
