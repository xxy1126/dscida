package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/tmo/dscida/internal/assets"
	"github.com/tmo/dscida/internal/store"
)

const DefaultIDA = "/Applications/IDA Professional 9.1.app/Contents/MacOS/idat"

type Runner struct {
	IDAT string
}

type Validation struct {
	Success                  bool   `json:"success"`
	IDBPath                  string `json:"idb_path"`
	IDAVersion               string `json:"ida_version"`
	LoadedImageBackend       string `json:"loaded_image_backend"`
	LoadedImageIndexes       []int  `json:"loaded_image_indices"`
	ExpectedLoadedImageIndex []int  `json:"expected_loaded_image_indices"`
	TargetKind               string `json:"target_kind"`
	InputPath                string `json:"input_path"`
	InputSHA256              string `json:"input_sha256"`
	NativeInput              struct {
		InputPath   string `json:"input_path"`
		InputSHA256 string `json:"input_sha256"`
		FileType    int    `json:"filetype"`
		Processor   string `json:"processor"`
	} `json:"native_input"`
	Error string `json:"error"`
}

type LaunchRecord struct {
	PID       int    `json:"pid"`
	IDAT      string `json:"idat"`
	StartedAt string `json:"started_at"`
}

func ResolveIDA(path string) (string, error) {
	if path == "" {
		path = DefaultIDA
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("find IDA: %w", err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "idat")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err = os.Stat(absolute); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("idat is not executable: %s", absolute)
	}
	return absolute, nil
}

func (r *Runner) PrepareScripts(sessionDir string) (string, string, error) {
	scriptDir := filepath.Join(sessionDir, "runtime", "scripts")
	if err := os.MkdirAll(scriptDir, 0o700); err != nil {
		return "", "", err
	}
	sidecar := filepath.Join(scriptDir, "dscida_sidecar.py")
	validator := filepath.Join(scriptDir, "dscida_validator.py")
	if err := writeAsset(sidecar, assets.Sidecar); err != nil {
		return "", "", err
	}
	if err := writeAsset(validator, assets.Validator); err != nil {
		return "", "", err
	}
	return sidecar, validator, nil
}

func writeAsset(path string, data []byte) error {
	temporary := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	file, err := os.Open(temporary)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	file.Close()
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return store.SyncDir(filepath.Dir(path))
}

type LaunchOptions struct {
	SessionDir        string
	SessionID         string
	SessionInstanceID string
	TargetKind        string
	DSCPath           string
	DSCUUID           string
	ModulePath        string
	Arch              string
	ImageCount        int
	SourcePath        string
	InputPath         string
	InputSHA256       string
	InputSize         int64
	BinaryFormat      string
	IDAProcessor      string
	MachOUUID         string
	WorkingIDB        string
	Token             string
	Host              string
	Port              int
	OpenExisting      bool
}

func (r *Runner) Launch(options LaunchOptions) (int, error) {
	sidecar, _, err := r.PrepareScripts(options.SessionDir)
	if err != nil {
		return 0, err
	}
	logDir := filepath.Join(options.SessionDir, "logs")
	stdout, err := os.OpenFile(filepath.Join(logDir, "idat.stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	stderr, err := os.OpenFile(filepath.Join(logDir, "idat.stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		stdout.Close()
		return 0, err
	}

	args := []string{"-A", "-a-", "-P+", "-L" + filepath.Join(logDir, "ida-message.log"), "-S" + sidecar}
	if options.OpenExisting {
		args = append(args, options.WorkingIDB)
	} else if options.TargetKind == store.TargetBinary {
		args = append(args, "-o"+options.WorkingIDB, options.InputPath)
	} else {
		loader := fmt.Sprintf("Apple DYLD cache for %s (select module(s))", options.Arch)
		args = append(args, "-T"+loader, "-o"+options.WorkingIDB, options.DSCPath)
	}
	command := exec.Command(r.IDAT, args...)
	command.Stdout = stdout
	command.Stderr = stderr
	command.Stdin = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Env = append(os.Environ(),
		"TVHEADLESS=1",
		"DSCIDA_HOST="+options.Host,
		"DSCIDA_PORT="+strconv.Itoa(options.Port),
		"DSCIDA_SESSION_DIR="+options.SessionDir,
		"DSCIDA_SESSION_ID="+options.SessionID,
		"DSCIDA_SESSION_INSTANCE_ID="+options.SessionInstanceID,
		"DSCIDA_CONTROL_TOKEN="+options.Token,
		"DSCIDA_TARGET_KIND="+options.TargetKind,
		"DSCIDA_IMAGE_COUNT="+strconv.Itoa(options.ImageCount),
		"DSCIDA_DSC_PATH="+options.DSCPath,
		"DSCIDA_DSC_UUID="+options.DSCUUID,
		"DSCIDA_MAIN_MODULE="+options.ModulePath,
		"DSCIDA_SOURCE_PATH="+options.SourcePath,
		"DSCIDA_INPUT_PATH="+options.InputPath,
		"DSCIDA_INPUT_SHA256="+options.InputSHA256,
		"DSCIDA_INPUT_SIZE="+strconv.FormatInt(options.InputSize, 10),
		"DSCIDA_BINARY_FORMAT="+options.BinaryFormat,
		"DSCIDA_ARCHITECTURE="+options.Arch,
		"DSCIDA_IDA_PROCESSOR="+options.IDAProcessor,
		"DSCIDA_MACHO_UUID="+options.MachOUUID,
	)
	if !options.OpenExisting && options.TargetKind != store.TargetBinary {
		command.Env = append(command.Env, "IDA_DYLD_CACHE_MODULE="+options.ModulePath)
	}
	if err := command.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return 0, err
	}
	record := LaunchRecord{
		PID: command.Process.Pid, IDAT: r.IDAT,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	launchPath := filepath.Join(options.SessionDir, "runtime", "launch.json")
	if err := store.WriteJSON(launchPath, record, 0o600); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		stdout.Close()
		stderr.Close()
		return 0, fmt.Errorf("persist IDA launch ownership: %w", err)
	}
	go func() {
		_ = command.Wait()
		_ = os.Remove(launchPath)
	}()
	stdout.Close()
	stderr.Close()
	return command.Process.Pid, nil
}

func LoadLaunchRecord(sessionDir string) (*LaunchRecord, error) {
	var record LaunchRecord
	if err := store.ReadJSON(filepath.Join(sessionDir, "runtime", "launch.json"), &record); err != nil {
		return nil, err
	}
	if record.PID <= 0 || record.IDAT == "" || record.StartedAt == "" {
		return nil, fmt.Errorf("invalid launch ownership record")
	}
	return &record, nil
}

func WaitReady(ctx context.Context, sessionDir string, pid int) (*store.Ready, error) {
	path := filepath.Join(sessionDir, "runtime", "ready.json")
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var ready store.Ready
		if err := store.ReadJSON(path, &ready); err == nil {
			if ready.PID != pid {
				return nil, fmt.Errorf("ready PID mismatch: launched %d, published %d", pid, ready.PID)
			}
			return &ready, nil
		}
		if !store.ProcessAlive(pid) {
			return nil, fmt.Errorf("idat process %d exited before readiness", pid)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Runner) Validate(ctx context.Context, sessionDir, snapshot string, expected []int, session *store.Session) (*Validation, error) {
	_, validator, err := r.PrepareScripts(sessionDir)
	if err != nil {
		return nil, err
	}
	validationDir, err := os.MkdirTemp(filepath.Join(sessionDir, "staging"), filepath.Base(snapshot)+".validation-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(validationDir, 0o700); err != nil {
		return nil, err
	}
	validationIDB := filepath.Join(validationDir, "candidate.i64")
	if err := store.CopyFile(snapshot, validationIDB, 0o600); err != nil {
		return nil, fmt.Errorf("copy validation candidate: %w", err)
	}
	resultPath := filepath.Join(validationDir, "result.json")
	expected = append([]int(nil), expected...)
	if expected == nil {
		expected = []int{}
	}
	sort.Ints(expected)
	expectedJSON, _ := json.Marshal(expected)
	logFile, err := os.OpenFile(filepath.Join(validationDir, "validator.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, r.IDAT, "-A", "-L"+filepath.Join(validationDir, "ida-message.log"), "-S"+validator, validationIDB)
	command.Env = append(os.Environ(),
		"TVHEADLESS=1",
		"DSCIDA_VALIDATION_RESULT="+resultPath,
		"DSCIDA_TARGET_KIND="+store.TargetKind(session),
		"DSCIDA_EXPECTED_INDEXES="+string(expectedJSON),
		"DSCIDA_IMAGE_COUNT="+strconv.Itoa(session.ImageCount),
		"DSCIDA_DSC_PATH="+session.DSCPath,
		"DSCIDA_DSC_UUID="+session.DSCUUID,
		"DSCIDA_MAIN_MODULE="+session.MainModule,
		"DSCIDA_SOURCE_PATH="+session.SourcePath,
		"DSCIDA_INPUT_PATH="+session.InputPath,
		"DSCIDA_INPUT_SHA256="+session.InputSHA256,
		"DSCIDA_INPUT_SIZE="+strconv.FormatInt(session.InputSize, 10),
		"DSCIDA_BINARY_FORMAT="+session.BinaryFormat,
		"DSCIDA_ARCHITECTURE="+session.Architecture,
		"DSCIDA_IDA_PROCESSOR="+session.IDAProcessor,
		"DSCIDA_MACHO_UUID="+session.MachOUUID,
	)
	command.Stdout = logFile
	command.Stderr = logFile
	runErr := command.Run()
	logFile.Close()
	var result Validation
	if err := store.ReadJSON(resultPath, &result); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("validator exited: %v; no result: %w", runErr, err)
		}
		return nil, fmt.Errorf("read validator result: %w", err)
	}
	if err := validateProcessResult(runErr, &result); err != nil {
		return &result, err
	}
	if store.TargetKind(session) == store.TargetDSC && !equalInts(result.LoadedImageIndexes, expected) {
		return &result, fmt.Errorf("validator index mismatch: got %v, expected %v", result.LoadedImageIndexes, expected)
	}
	if err := os.RemoveAll(validationDir); err != nil {
		return &result, fmt.Errorf("remove successful validation copy: %w", err)
	}
	return &result, nil
}

func validateProcessResult(runErr error, result *Validation) error {
	if runErr != nil {
		return fmt.Errorf("validator did not exit cleanly: %v: %s", runErr, result.Error)
	}
	if !result.Success {
		return fmt.Errorf("validation failed: %s", result.Error)
	}
	return nil
}

func CopyGenerationToWorking(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if command := exec.Command("cp", "-c", source, destination); command.Run() == nil {
		return os.Chmod(destination, 0o600)
	}
	if err := store.CopyFile(source, destination, 0o600); err != nil {
		return err
	}
	return os.Chmod(destination, 0o600)
}

func Tail(path string, lines int, output io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	start := len(data)
	for count := 0; start > 0 && count <= lines; {
		start--
		if data[start] == '\n' {
			count++
		}
	}
	_, err = output.Write(data[start:])
	return err
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
