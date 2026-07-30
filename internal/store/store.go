package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	SchemaVersion        = 1
	SessionSchemaVersion = 2
)

var terminalJobs = map[string]bool{
	"succeeded":               true,
	"failed":                  true,
	"interrupted_rolled_back": true,
	"outcome_unknown_live":    true,
	"cancelled_before_start":  true,
}

var jobTransitions = map[string]map[string]bool{
	"queued": {
		"queued": true, "running_dscu": true, "snapshotting": true,
		"failed": true, "cancelled_before_start": true, "outcome_unknown_live": true,
	},
	"running_dscu": {
		"running_dscu": true, "running_analysis": true, "succeeded": true,
		"failed": true, "interrupted_rolled_back": true, "outcome_unknown_live": true,
	},
	"running_analysis": {
		"running_analysis": true, "snapshotting": true, "failed": true,
		"interrupted_rolled_back": true, "outcome_unknown_live": true,
	},
	"snapshotting": {
		"snapshotting": true, "validating": true, "failed": true,
		"interrupted_rolled_back": true, "outcome_unknown_live": true,
	},
	"validating": {
		"validating": true, "committing": true, "failed": true,
		"interrupted_rolled_back": true,
	},
	"committing": {
		"committing": true, "succeeded": true, "failed": true,
		"interrupted_rolled_back": true,
	},
}

type Session struct {
	SchemaVersion       int      `json:"schema_version"`
	SessionID           string   `json:"session_id"`
	SessionInstanceID   string   `json:"session_instance_id,omitempty"`
	State               string   `json:"state"`
	DSCPath             string   `json:"dsc_path"`
	DSCUUID             string   `json:"dsc_uuid"`
	Architecture        string   `json:"architecture"`
	MainModule          string   `json:"main_module"`
	ImageCount          int      `json:"image_count"`
	LoadedModules       []string `json:"loaded_modules"`
	ImplicitlyLoaded    []string `json:"implicitly_loaded_modules"`
	LoadedImageIndexes  []int    `json:"committed_loaded_image_indexes"`
	ActiveJobIDs        []string `json:"active_job_ids"`
	CurrentGeneration   int      `json:"current_generation"`
	CurrentPath         string   `json:"current_generation_path,omitempty"`
	CurrentSHA256       string   `json:"current_generation_sha256,omitempty"`
	WorkingIDBPath      string   `json:"working_idb_path"`
	IDAPID              int      `json:"ida_pid,omitempty"`
	ControlURL          string   `json:"control_url,omitempty"`
	MCPURL              string   `json:"mcp_url,omitempty"`
	ControlToken        string   `json:"-"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
	UncommittedMCPEdits bool     `json:"uncommitted_mcp_edits_possible"`
}

type Secret struct {
	ControlToken string `json:"control_token"`
}

type Job struct {
	SchemaVersion      int            `json:"schema_version"`
	JobID              string         `json:"job_id"`
	RequestID          string         `json:"request_id"`
	PayloadHash        string         `json:"payload_hash"`
	SessionID          string         `json:"session_id"`
	Operation          string         `json:"operation"`
	State              string         `json:"state"`
	ModulePath         string         `json:"module_path,omitempty"`
	ImageIndex         *int           `json:"image_index,omitempty"`
	BaseGeneration     int            `json:"base_generation"`
	IDAPID             int            `json:"ida_pid,omitempty"`
	SnapshotPath       string         `json:"snapshot_path,omitempty"`
	LoadedImageIndexes []int          `json:"loaded_image_indices,omitempty"`
	LoadedImageBackend string         `json:"loaded_image_backend,omitempty"`
	Error              string         `json:"error,omitempty"`
	Result             map[string]any `json:"result,omitempty"`
	CreatedAt          string         `json:"created_at"`
	UpdatedAt          string         `json:"updated_at"`
	CompletedAt        string         `json:"completed_at,omitempty"`
}

type Current struct {
	SchemaVersion      int    `json:"schema_version"`
	Generation         int    `json:"generation"`
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	DSCPath            string `json:"dsc_path"`
	DSCUUID            string `json:"dsc_uuid"`
	MainModule         string `json:"main_module"`
	LoadedImageIndexes []int  `json:"loaded_image_indexes"`
	IDAVersion         string `json:"ida_version"`
	CreatedAt          string `json:"created_at"`
}

type Ready struct {
	Success           bool   `json:"success"`
	State             string `json:"state"`
	SessionID         string `json:"session_id"`
	SessionInstanceID string `json:"session_instance_id"`
	PID               int    `json:"pid"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	MCPURL            string `json:"mcp_url"`
	ControlURL        string `json:"control_url"`
	IDA               struct {
		IDBPath            string `json:"idb_path"`
		LoadedImageBackend string `json:"loaded_image_backend"`
		LoadedImageIndexes []int  `json:"loaded_image_indices"`
	} `json:"ida"`
}

type Store struct {
	Root string
}

func DefaultRoot() (string, error) {
	if value := os.Getenv("DSCIDA_HOME"); value != "" {
		return filepath.Abs(value)
	}
	userConfig, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userConfig, "dscida"), nil
}

func New(root string) (*Store, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(absolute, "sessions"), 0o700); err != nil {
		return nil, err
	}
	return &Store{Root: absolute}, nil
}

func (s *Store) SessionDir(id string) string {
	return filepath.Join(s.Root, "sessions", id)
}

func (s *Store) Initialize(session *Session) error {
	dir := s.SessionDir(session.SessionID)
	for _, subdir := range []string{"generations", "runtime", "jobs", "staging", "recovery", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "session.json")); err == nil {
		return fmt.Errorf("session already exists: %s", session.SessionID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	session.SchemaVersion = SessionSchemaVersion
	instanceID, err := RandomID("instance-", 16)
	if err != nil {
		return err
	}
	session.SessionInstanceID = instanceID
	session.CreatedAt = now
	session.UpdatedAt = now
	if err := WriteJSON(filepath.Join(dir, "secret.json"), Secret{ControlToken: session.ControlToken}, 0o600); err != nil {
		return err
	}
	return s.SaveSession(session)
}

func (s *Store) LoadSession(id string) (*Session, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid session ID %q", id)
	}
	var session Session
	if err := ReadJSON(filepath.Join(s.SessionDir(id), "session.json"), &session); err != nil {
		return nil, err
	}
	if (session.SchemaVersion != SchemaVersion && session.SchemaVersion != SessionSchemaVersion) ||
		session.SessionID != id {
		return nil, fmt.Errorf("session identity or schema mismatch for %s", id)
	}
	if session.SchemaVersion == SessionSchemaVersion && !ValidID(session.SessionInstanceID) {
		return nil, fmt.Errorf("session %s has invalid instance identity", id)
	}
	if err := validateEndpoint(session.ControlURL, "/control"); err != nil {
		return nil, fmt.Errorf("invalid persisted control URL: %w", err)
	}
	if err := validateEndpoint(session.MCPURL, "/mcp"); err != nil {
		return nil, fmt.Errorf("invalid persisted MCP URL: %w", err)
	}
	for _, path := range []string{session.WorkingIDBPath, session.CurrentPath} {
		if path != "" && !within(s.SessionDir(id), path) {
			return nil, fmt.Errorf("persisted session path escapes session directory: %s", path)
		}
	}
	var secret Secret
	if err := ReadJSON(filepath.Join(s.SessionDir(id), "secret.json"), &secret); err != nil {
		return nil, err
	}
	session.ControlToken = secret.ControlToken
	return &session, nil
}

func (s *Store) SaveSession(session *Session) error {
	if session.SchemaVersion == SessionSchemaVersion && !ValidID(session.SessionInstanceID) {
		return fmt.Errorf("session %s has invalid instance identity", session.SessionID)
	}
	var existing Session
	sessionPath := filepath.Join(s.SessionDir(session.SessionID), "session.json")
	if err := ReadJSON(sessionPath, &existing); err == nil {
		if existing.SchemaVersion == SessionSchemaVersion &&
			existing.SessionInstanceID != session.SessionInstanceID {
			return fmt.Errorf("session %s instance identity is immutable", session.SessionID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read session before save: %w", err)
	}
	session.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return WriteJSON(sessionPath, session, 0o600)
}

func (s *Store) ListSessions() ([]Session, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "sessions"))
	if err != nil {
		return nil, err
	}
	var sessions []Session
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		session, err := s.LoadSession(entry.Name())
		if err == nil {
			session.ControlToken = ""
			sessions = append(sessions, *session)
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CreatedAt < sessions[j].CreatedAt })
	return sessions, nil
}

func (s *Store) NewJob(session *Session, operation, module string, index *int) (*Job, error) {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	*session = *fresh
	if len(session.ActiveJobIDs) > 0 {
		return nil, fmt.Errorf("session is busy with job %s", session.ActiveJobIDs[0])
	}
	initialCheckpoint := operation == "save" && session.CurrentGeneration == 0 && session.State == "checkpointing_initial"
	if session.State != "ready" && !initialCheckpoint {
		return nil, fmt.Errorf("session %s is %s, not ready", session.SessionID, session.State)
	}
	id, err := RandomID("job-", 12)
	if err != nil {
		return nil, err
	}
	requestID, err := RandomID("req-", 12)
	if err != nil {
		return nil, err
	}
	indexValue := -1
	if index != nil {
		indexValue = *index
	}
	payload := fmt.Sprintf("%s\x00%s\x00%d\x00%d", operation, module, indexValue, session.CurrentGeneration)
	sum := sha256.Sum256([]byte(payload))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	job := &Job{
		SchemaVersion:  SchemaVersion,
		JobID:          id,
		RequestID:      requestID,
		PayloadHash:    hex.EncodeToString(sum[:]),
		SessionID:      session.SessionID,
		Operation:      operation,
		State:          "queued",
		ModulePath:     module,
		ImageIndex:     index,
		BaseGeneration: session.CurrentGeneration,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.SaveJob(job); err != nil {
		return nil, err
	}
	session.ActiveJobIDs = []string{id}
	if err := s.SaveSession(session); err != nil {
		return nil, err
	}
	return job, nil
}

func (s *Store) JobPath(sessionID, jobID string) string {
	return filepath.Join(s.SessionDir(sessionID), "jobs", jobID+".json")
}

func (s *Store) SaveJob(job *Job) error {
	path := s.JobPath(job.SessionID, job.JobID)
	if !ValidID(job.SessionID) || !ValidID(job.JobID) {
		return fmt.Errorf("invalid job or session identity")
	}
	var prior Job
	if err := ReadJSON(path, &prior); err == nil {
		if terminalJobs[prior.State] {
			return fmt.Errorf("terminal job %s is immutable in state %s", job.JobID, prior.State)
		}
		if !terminalJobs[prior.State] && !jobTransitions[prior.State][job.State] {
			return fmt.Errorf("invalid job transition %s -> %s", prior.State, job.State)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing job before update: %w", err)
	}
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if terminalJobs[job.State] && job.CompletedAt == "" {
		job.CompletedAt = job.UpdatedAt
	}
	return WriteJSON(path, job, 0o600)
}

func (s *Store) LoadJob(sessionID, jobID string) (*Job, error) {
	if !ValidID(sessionID) || !ValidID(jobID) {
		return nil, fmt.Errorf("invalid job or session identity")
	}
	var job Job
	if err := ReadJSON(s.JobPath(sessionID, jobID), &job); err != nil {
		return nil, err
	}
	if job.SchemaVersion != SchemaVersion || job.SessionID != sessionID || job.JobID != jobID {
		return nil, fmt.Errorf("job identity or schema mismatch for %s", jobID)
	}
	if job.SnapshotPath != "" && !within(s.SessionDir(sessionID), job.SnapshotPath) {
		return nil, fmt.Errorf("job snapshot path escapes session directory")
	}
	return &job, nil
}

func (s *Store) FindJob(jobID string) (*Job, error) {
	if !ValidID(jobID) {
		return nil, fmt.Errorf("invalid job ID %q", jobID)
	}
	sessions, err := os.ReadDir(filepath.Join(s.Root, "sessions"))
	if err != nil {
		return nil, err
	}
	for _, entry := range sessions {
		if entry.IsDir() {
			job, err := s.LoadJob(entry.Name(), jobID)
			if err == nil {
				return job, nil
			}
		}
	}
	return nil, fmt.Errorf("job not found: %s", jobID)
}

func (s *Store) ListJobs(sessionID string) ([]Job, error) {
	if !ValidID(sessionID) {
		return nil, fmt.Errorf("invalid session ID %q", sessionID)
	}
	entries, err := os.ReadDir(filepath.Join(s.SessionDir(sessionID), "jobs"))
	if err != nil {
		return nil, err
	}
	var jobs []Job
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var job Job
		if ReadJSON(filepath.Join(s.SessionDir(sessionID), "jobs", entry.Name()), &job) == nil {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt < jobs[j].CreatedAt })
	return jobs, nil
}

func (s *Store) Commit(session *Session, job *Job, snapshot string, indexes []int, idaVersion string) (*Current, error) {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	*session = *fresh
	if session.CurrentGeneration != job.BaseGeneration {
		return nil, fmt.Errorf("stale base generation: job=%d current=%d", job.BaseGeneration, session.CurrentGeneration)
	}
	if len(session.ActiveJobIDs) != 1 || session.ActiveJobIDs[0] != job.JobID {
		return nil, fmt.Errorf("job %s does not own the session mutation slot", job.JobID)
	}
	freshJob, err := s.LoadJob(session.SessionID, job.JobID)
	if err != nil {
		return nil, err
	}
	if freshJob.State != "validating" {
		return nil, fmt.Errorf("job %s is %s, not validating", job.JobID, freshJob.State)
	}
	if freshJob.BaseGeneration != session.CurrentGeneration {
		return nil, fmt.Errorf("job base generation changed during finalization")
	}
	*job = *freshJob
	next := session.CurrentGeneration + 1
	generationName := fmt.Sprintf("%06d.i64", next)
	generationPath := filepath.Join(s.SessionDir(session.SessionID), "generations", generationName)
	if _, err := os.Stat(generationPath); err == nil {
		orphanName := fmt.Sprintf("orphan-%s-%s", generationName, time.Now().UTC().Format("20060102T150405.000000000Z"))
		orphanPath := filepath.Join(s.SessionDir(session.SessionID), "recovery", orphanName)
		if err := os.Rename(generationPath, orphanPath); err != nil {
			return nil, fmt.Errorf("quarantine orphan generation: %w", err)
		}
		if err := SyncDir(filepath.Dir(generationPath)); err != nil {
			return nil, err
		}
		if err := SyncDir(filepath.Dir(orphanPath)); err != nil {
			return nil, err
		}
	}
	sum, err := SHA256File(snapshot)
	if err != nil {
		return nil, err
	}
	job.State = "committing"
	if err := s.SaveJob(job); err != nil {
		return nil, err
	}
	if err := os.Rename(snapshot, generationPath); err != nil {
		return nil, fmt.Errorf("commit generation: %w", err)
	}
	generation, err := os.Open(generationPath)
	if err != nil {
		return nil, err
	}
	if err := generation.Sync(); err != nil {
		generation.Close()
		return nil, err
	}
	generation.Close()
	if err := os.Chmod(generationPath, 0o400); err != nil {
		return nil, err
	}
	if err := SyncDir(filepath.Dir(generationPath)); err != nil {
		return nil, err
	}
	current := &Current{
		SchemaVersion:      SchemaVersion,
		Generation:         next,
		Path:               generationPath,
		SHA256:             sum,
		DSCPath:            session.DSCPath,
		DSCUUID:            session.DSCUUID,
		MainModule:         session.MainModule,
		LoadedImageIndexes: append([]int(nil), indexes...),
		IDAVersion:         idaVersion,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := WriteJSON(filepath.Join(s.SessionDir(session.SessionID), "current.json"), current, 0o600); err != nil {
		return nil, err
	}
	session.CurrentGeneration = next
	session.CurrentPath = generationPath
	session.CurrentSHA256 = sum
	session.LoadedImageIndexes = append([]int(nil), indexes...)
	session.ActiveJobIDs = nil
	session.State = "ready"
	if job.Operation == "add" && job.ModulePath != "" && !contains(session.LoadedModules, job.ModulePath) {
		session.LoadedModules = append(session.LoadedModules, job.ModulePath)
	}
	if err := s.SaveSession(session); err != nil {
		return nil, err
	}
	job.State = "succeeded"
	job.LoadedImageIndexes = append([]int(nil), indexes...)
	job.Result = map[string]any{"generation": next, "path": generationPath, "sha256": sum}
	if err := s.SaveJob(job); err != nil {
		return nil, err
	}
	return current, nil
}

func (s *Store) LoadCurrent(session *Session) (*Current, error) {
	var current Current
	if err := ReadJSON(filepath.Join(s.SessionDir(session.SessionID), "current.json"), &current); err != nil {
		return nil, err
	}
	if current.SchemaVersion != SchemaVersion || current.Generation <= 0 ||
		current.DSCPath != session.DSCPath ||
		current.DSCUUID != session.DSCUUID ||
		current.MainModule != session.MainModule {
		return nil, fmt.Errorf("current generation identity mismatch")
	}
	expectedPath := filepath.Join(
		s.SessionDir(session.SessionID), "generations",
		fmt.Sprintf("%06d.i64", current.Generation),
	)
	if !SamePath(expectedPath, current.Path) {
		return nil, fmt.Errorf("current generation path is not the canonical generation file")
	}
	info, err := os.Lstat(current.Path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return nil, fmt.Errorf("current generation must be a regular read-only file")
	}
	sum, err := SHA256File(current.Path)
	if err != nil {
		return nil, err
	}
	if sum != current.SHA256 {
		return nil, fmt.Errorf("current generation SHA256 mismatch: expected %s, got %s", current.SHA256, sum)
	}
	return &current, nil
}

func (s *Store) BackupSession(session *Session) (string, error) {
	if ProcessAlive(session.IDAPID) {
		return "", fmt.Errorf("session %s still has a live IDA process", session.SessionID)
	}
	source := s.SessionDir(session.SessionID)
	backupName := fmt.Sprintf("%s-backup-%s", session.SessionID, time.Now().UTC().Format("20060102T150405.000000000Z"))
	destination := filepath.Join(s.Root, "sessions", backupName)
	if err := os.Rename(source, destination); err != nil {
		return "", err
	}
	if err := SyncDir(filepath.Dir(source)); err != nil {
		return "", err
	}
	return destination, nil
}

func (s *Store) PrepareResume(session *Session) (*Current, error) {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return nil, err
	}
	if ProcessAlive(fresh.IDAPID) {
		return nil, fmt.Errorf("session %s already has a live IDA process", fresh.SessionID)
	}
	if fresh.SchemaVersion == SchemaVersion {
		instanceID, err := RandomID("instance-", 16)
		if err != nil {
			return nil, fmt.Errorf("upgrade legacy session identity: %w", err)
		}
		fresh.SchemaVersion = SessionSchemaVersion
		fresh.SessionInstanceID = instanceID
	}
	current, err := s.LoadCurrent(fresh)
	if err != nil {
		fresh.State = "recovery_required"
		_ = s.SaveSession(fresh)
		return nil, err
	}
	for _, jobID := range fresh.ActiveJobIDs {
		job, loadErr := s.LoadJob(fresh.SessionID, jobID)
		if loadErr == nil && !IsTerminalJob(job.State) {
			if job.State == "committing" && current.Generation > job.BaseGeneration {
				job.State = "succeeded"
				job.LoadedImageIndexes = append([]int(nil), current.LoadedImageIndexes...)
				job.Result = map[string]any{
					"generation": current.Generation, "path": current.Path,
					"sha256": current.SHA256, "recovered_after_pointer_commit": true,
				}
				if job.Operation == "add" && job.ModulePath != "" && !contains(fresh.LoadedModules, job.ModulePath) {
					fresh.LoadedModules = append(fresh.LoadedModules, job.ModulePath)
				}
			} else if job.State == "queued" {
				job.State = "cancelled_before_start"
			} else {
				job.State = "interrupted_rolled_back"
			}
			job.Error = "IDA exited before job completion; rolled back to current generation"
			if err := s.SaveJob(job); err != nil {
				return nil, err
			}
		}
	}
	fresh.ActiveJobIDs = nil
	fresh.CurrentGeneration = current.Generation
	fresh.CurrentPath = current.Path
	fresh.CurrentSHA256 = current.SHA256
	fresh.LoadedImageIndexes = append([]int(nil), current.LoadedImageIndexes...)
	fresh.State = "creating"
	fresh.IDAPID = 0
	fresh.ControlURL = ""
	fresh.MCPURL = ""
	runtimePath := filepath.Join(s.SessionDir(fresh.SessionID), "runtime")
	if _, err := os.Stat(runtimePath); err == nil {
		recoveryName := "runtime-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		recoveryPath := filepath.Join(s.SessionDir(fresh.SessionID), "recovery", recoveryName)
		if err := os.Rename(runtimePath, recoveryPath); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(runtimePath, 0o700); err != nil {
		return nil, err
	}
	fresh.WorkingIDBPath = filepath.Join(runtimePath, "working.i64")
	if err := s.SaveSession(fresh); err != nil {
		return nil, err
	}
	*session = *fresh
	return current, nil
}

func (s *Store) LockFinalizer(sessionID, jobID string) (func(), error) {
	if !ValidID(sessionID) || !ValidID(jobID) {
		return nil, fmt.Errorf("invalid job or session identity")
	}
	path := filepath.Join(s.SessionDir(sessionID), "jobs", jobID+".finalizer.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (s *Store) ClearActiveJob(session *Session, jobID, state string) error {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return err
	}
	if len(fresh.ActiveJobIDs) == 0 {
		*session = *fresh
		return nil
	}
	if len(fresh.ActiveJobIDs) != 1 || fresh.ActiveJobIDs[0] != jobID {
		return fmt.Errorf("job %s does not own the session mutation slot", jobID)
	}
	fresh.ActiveJobIDs = nil
	fresh.State = state
	if err := s.SaveSession(fresh); err != nil {
		return err
	}
	*session = *fresh
	return nil
}

func (s *Store) LockLifecycle(sessionID string) (func(), error) {
	if !ValidID(sessionID) {
		return nil, fmt.Errorf("invalid session ID %q", sessionID)
	}
	path := filepath.Join(s.Root, "sessions", "."+sessionID+".lifecycle.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (s *Store) BeginStop(session *Session, force bool) error {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return err
	}
	if len(fresh.ActiveJobIDs) > 0 && !force {
		return fmt.Errorf("session is busy with job %s", fresh.ActiveJobIDs[0])
	}
	fresh.State = "stopping"
	if err := s.SaveSession(fresh); err != nil {
		return err
	}
	*session = *fresh
	return nil
}

func (s *Store) UpdateImplicitModules(session *Session, modules []string) error {
	unlock, err := s.lockSession(session.SessionID)
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := s.LoadSession(session.SessionID)
	if err != nil {
		return err
	}
	fresh.ImplicitlyLoaded = append([]string(nil), modules...)
	if err := s.SaveSession(fresh); err != nil {
		return err
	}
	*session = *fresh
	return nil
}

func (s *Store) lockSession(sessionID string) (func(), error) {
	path := filepath.Join(s.SessionDir(sessionID), "session.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func WriteJSON(path string, value any, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary := filepath.Join(parent, "."+filepath.Base(path)+".tmp-"+strconv.Itoa(os.Getpid()))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	return SyncDir(parent)
}

func ReadJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(value)
}

func SyncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CopyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func RandomID(prefix string, bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func ValidID(value string) bool {
	if value == "" || len(value) > 96 || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func within(parent, child string) bool {
	parent, ok := canonicalPath(parent)
	if !ok {
		return false
	}
	child, ok = canonicalPath(child)
	if !ok {
		return false
	}
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func SamePath(first, second string) bool {
	first, firstOK := canonicalPath(first)
	second, secondOK := canonicalPath(second)
	return firstOK && secondOK && first == second
}

// canonicalPath resolves symlinks in the longest existing path prefix. This is
// needed on macOS where os.MkdirTemp commonly returns /var/... while tools
// running in another process report the same path as /private/var/....
func canonicalPath(path string) (string, bool) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	current := filepath.Clean(absolute)
	var suffix []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", false
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), true
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func validateEndpoint(rawURL, expectedPath string) error {
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" || parsed.Path != expectedPath || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("unexpected endpoint form")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("endpoint is not loopback")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("endpoint has no valid TCP port")
	}
	return nil
}

func ValidateEndpointPair(controlURL, mcpURL string) error {
	if err := validateEndpoint(controlURL, "/control"); err != nil {
		return fmt.Errorf("invalid control endpoint: %w", err)
	}
	if err := validateEndpoint(mcpURL, "/mcp"); err != nil {
		return fmt.Errorf("invalid MCP endpoint: %w", err)
	}
	controlEndpoint, _ := url.Parse(controlURL)
	mcpEndpoint, _ := url.Parse(mcpURL)
	if controlEndpoint.Scheme != mcpEndpoint.Scheme ||
		controlEndpoint.Hostname() != mcpEndpoint.Hostname() ||
		controlEndpoint.Port() != mcpEndpoint.Port() {
		return fmt.Errorf("control and MCP endpoints do not share one listener")
	}
	return nil
}

func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func IsTerminalJob(state string) bool { return terminalJobs[state] }

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
