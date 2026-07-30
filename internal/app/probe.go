package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tmo/dscida/internal/cache"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

type probeStep struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	DurationMS float64        `json:"duration_ms"`
	Error      string         `json:"error,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type dscProbeResult struct {
	Success     bool        `json:"success"`
	DSCPath     string      `json:"dsc_path"`
	ModulePath  string      `json:"module_path"`
	AddModule   string      `json:"add_module,omitempty"`
	SessionID   string      `json:"session_id"`
	ArtifactDir string      `json:"artifact_dir,omitempty"`
	Cleaned     bool        `json:"cleaned"`
	Steps       []probeStep `json:"steps"`
}

func (e *environment) runDSCProbe(dscPath, modulePath, addModule, idat string, timeout time.Duration, keep bool) (*dscProbeResult, error) {
	result := &dscProbeResult{
		DSCPath: dscPath, ModulePath: modulePath, AddModule: addModule,
	}
	started := time.Now()
	info, err := cache.Open(dscPath)
	if err != nil {
		result.addStep("module_resolution", started, err, nil)
		return result, err
	}
	primary, err := info.Exact(modulePath)
	if err != nil {
		result.addStep("module_resolution", started, err, nil)
		return result, err
	}
	var additional *cache.Module
	if addModule != "" {
		if addModule == modulePath {
			err = fmt.Errorf("--add-module must differ from the primary --module")
			result.addStep("module_resolution", started, err, nil)
			return result, err
		}
		resolved, resolveErr := info.Exact(addModule)
		if resolveErr != nil {
			result.addStep("module_resolution", started, resolveErr, nil)
			return result, resolveErr
		}
		additional = &resolved
	}
	result.DSCPath = info.Path
	result.ModulePath = primary.ModulePath
	result.addStep("module_resolution", started, nil, map[string]any{
		"dsc_uuid": info.UUID, "architecture": info.Architecture,
		"image_count": info.ImageCount, "primary_image_index": primary.ImageIndex,
	})

	probeRoot, err := os.MkdirTemp("", "dscida-probe-")
	if err != nil {
		return result, err
	}
	if err := os.Chmod(probeRoot, 0o700); err != nil {
		return result, err
	}
	result.ArtifactDir = probeRoot
	retainOnFailure := false
	defer func() {
		if !result.Success && !retainOnFailure {
			if os.RemoveAll(probeRoot) == nil {
				result.Cleaned = true
				result.ArtifactDir = ""
			}
		}
	}()
	random, err := store.RandomID("probe-", 6)
	if err != nil {
		return result, err
	}
	result.SessionID = random
	child := &environment{stdout: io.Discard, stderr: e.stderr}
	st, err := rootStore(probeRoot)
	if err != nil {
		return result, err
	}
	cleanup := func() {
		session, loadErr := st.LoadSession(result.SessionID)
		pid := 0
		if loadErr == nil {
			pid = session.IDAPID
		}
		if pid <= 0 {
			record, recordErr := runner.LoadLaunchRecord(st.SessionDir(result.SessionID))
			if recordErr == nil && store.SamePath(record.IDAT, idat) {
				pid = record.PID
			}
		}
		if !store.ProcessAlive(pid) {
			return
		}
		if loadErr == nil && session.IDAPID == pid {
			_ = child.stop([]string{
				result.SessionID, "--state-dir", probeRoot, "--ida-path", idat,
				"--no-save", "--timeout", "1m", "--json",
			})
		}
		if store.ProcessAlive(pid) {
			_ = waitOrTerminate(pid, 2*time.Second)
		}
	}
	defer func() {
		if !result.Success {
			cleanup()
		}
	}()

	started = time.Now()
	retainOnFailure = true
	err = child.start([]string{
		info.Path, "--module", primary.ModulePath, "--session", result.SessionID,
		"--output-dir", probeRoot, "--ida-path", idat, "--timeout", timeout.String(),
		"--json",
	})
	if err != nil {
		result.addStep("headless_start", started, err, nil)
		return result, err
	}
	session, err := st.LoadSession(result.SessionID)
	if err != nil {
		result.addStep("headless_start", started, err, nil)
		return result, err
	}
	result.addStep("headless_start", started, nil, map[string]any{
		"ida_pid": session.IDAPID, "control_url": session.ControlURL,
		"mcp_url": session.MCPURL, "generation": session.CurrentGeneration,
	})

	started = time.Now()
	var live struct {
		Success bool `json:"success"`
		PID     int  `json:"pid"`
		IDA     struct {
			IDBPath            string `json:"idb_path"`
			LoadedImageBackend string `json:"loaded_image_backend"`
			LoadedImageIndexes []int  `json:"loaded_image_indices"`
		} `json:"ida"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = control.New(session.ControlURL, session.ControlToken).Get(ctx, "/control/status", &live)
	cancel()
	if err == nil && (!live.Success || live.PID != session.IDAPID ||
		!slices.Contains(live.IDA.LoadedImageIndexes, int(primary.ImageIndex)) ||
		live.IDA.LoadedImageBackend == "") {
		err = fmt.Errorf("control/DSCU ownership or loaded-image validation failed")
	}
	result.addStep("dscu_loaded_image_backend", started, err, map[string]any{
		"backend": live.IDA.LoadedImageBackend, "loaded_image_indexes": live.IDA.LoadedImageIndexes,
		"idb_path": live.IDA.IDBPath,
	})
	if err != nil {
		return result, err
	}

	started = time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	health, err := control.MCPServerHealth(ctx, session.MCPURL)
	cancel()
	if err == nil && (!health.AutoAnalysisReady || !store.SamePath(health.IDBPath, session.WorkingIDBPath) ||
		!store.SamePath(health.InputPath, session.DSCPath)) {
		err = fmt.Errorf("MCP server_health identity or analysis readiness mismatch")
	}
	healthDetails := map[string]any{}
	if health != nil {
		healthDetails = map[string]any{
			"status": health.Status, "idb_path": health.IDBPath,
			"input_path": health.InputPath, "auto_analysis_ready": health.AutoAnalysisReady,
			"hexrays_ready": health.HexRaysReady,
		}
	}
	result.addStep("mcp_server_health", started, err, healthDetails)
	if err != nil {
		return result, err
	}

	started = time.Now()
	current, err := st.LoadCurrent(session)
	if err == nil && (current.Generation != 1 ||
		!slices.Contains(current.LoadedImageIndexes, int(primary.ImageIndex))) {
		err = fmt.Errorf("initial verified generation has unexpected identity")
	}
	generationDetails := map[string]any{}
	if current != nil {
		generationDetails = map[string]any{
			"generation": current.Generation, "path": current.Path,
			"sha256": current.SHA256, "loaded_image_indexes": current.LoadedImageIndexes,
		}
	}
	result.addStep("snapshot_reopen_validation", started, err, generationDetails)
	if err != nil {
		return result, err
	}

	if additional != nil {
		started = time.Now()
		err = child.add([]string{
			result.SessionID, "--state-dir", probeRoot, "--ida-path", idat,
			"--module", additional.ModulePath, "--timeout", timeout.String(), "--json",
		})
		session, loadErr := st.LoadSession(result.SessionID)
		if err == nil && loadErr != nil {
			err = loadErr
		}
		if err == nil && (!slices.Contains(session.LoadedImageIndexes, int(primary.ImageIndex)) ||
			!slices.Contains(session.LoadedImageIndexes, int(additional.ImageIndex)) ||
			session.CurrentGeneration < 2) {
			err = fmt.Errorf("incremental module load did not commit the expected indexes")
		}
		details := map[string]any{"module_path": additional.ModulePath, "image_index": additional.ImageIndex}
		if session != nil {
			details["generation"] = session.CurrentGeneration
			details["loaded_image_indexes"] = session.LoadedImageIndexes
			details["ida_pid"] = session.IDAPID
		}
		result.addStep("incremental_module_add", started, err, details)
		if err != nil {
			return result, err
		}
	} else {
		result.Steps = append(result.Steps, probeStep{Name: "incremental_module_add", Status: "skipped"})
	}

	started = time.Now()
	err = child.stop([]string{
		result.SessionID, "--state-dir", probeRoot, "--ida-path", idat,
		"--no-save", "--timeout", "2m", "--json",
	})
	if err == nil {
		session, loadErr := st.LoadSession(result.SessionID)
		if loadErr != nil {
			err = loadErr
		} else if store.ProcessAlive(session.IDAPID) || session.State != "stopped" {
			err = fmt.Errorf("probe IDA did not stop cleanly")
		}
	}
	result.addStep("shutdown", started, err, nil)
	if err != nil {
		return result, err
	}

	result.Success = true
	if !keep {
		started = time.Now()
		if err := os.RemoveAll(probeRoot); err != nil {
			result.Success = false
			result.addStep("cleanup", started, err, map[string]any{"artifact_dir": probeRoot})
			return result, err
		}
		result.Cleaned = true
		result.ArtifactDir = ""
		result.addStep("cleanup", started, nil, nil)
	} else {
		result.Steps = append(result.Steps, probeStep{
			Name: "cleanup", Status: "skipped",
			Details: map[string]any{"artifact_dir": probeRoot},
		})
	}
	return result, nil
}

func (r *dscProbeResult) addStep(name string, started time.Time, err error, details map[string]any) {
	status := "pass"
	errorText := ""
	if err != nil {
		status = "fail"
		errorText = err.Error()
	}
	r.Steps = append(r.Steps, probeStep{
		Name: name, Status: status,
		DurationMS: float64(time.Since(started).Microseconds()) / 1000,
		Error:      errorText, Details: details,
	})
}

func probeArtifactPath(result *dscProbeResult) string {
	if result == nil || result.ArtifactDir == "" {
		return ""
	}
	absolute, err := filepath.Abs(result.ArtifactDir)
	if err != nil {
		return result.ArtifactDir
	}
	return absolute
}
