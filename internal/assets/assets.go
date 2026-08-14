package assets

import (
	"embed"
	"fmt"
)

//go:embed dscida_sidecar.py
var Sidecar []byte

//go:embed dscida_validator.py
var Validator []byte

//go:embed scripts/*.py
var scriptFiles embed.FS

// Script returns the source of one embedded analysis-script template.
func Script(name string) (string, error) {
	data, err := scriptFiles.ReadFile("scripts/" + name)
	if err != nil {
		return "", fmt.Errorf("embedded script %q: %w", name, err)
	}
	return string(data), nil
}
