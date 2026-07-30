package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type logger struct {
	path   string
	stderr io.Writer
}

func newLogger(sessionDir string, stderr io.Writer) *logger {
	return &logger{path: filepath.Join(sessionDir, "logs", "dscida.jsonl"), stderr: stderr}
}

func (l *logger) event(level, component, event, message string, fields map[string]any) {
	record := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level, "component": component, "event": event, "message": message,
	}
	for key, value := range fields {
		record[key] = value
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		_ = json.NewEncoder(file).Encode(record)
		_ = file.Sync()
		_ = file.Close()
	}
	fmt.Fprintf(l.stderr, "[%s] %s\n", component, message)
}
