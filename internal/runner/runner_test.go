package runner

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatorSuccessRequiresCleanProcessExit(t *testing.T) {
	result := &Validation{Success: true}
	err := validateProcessResult(errors.New("signal: killed"), result)
	if err == nil || !strings.Contains(err.Error(), "did not exit cleanly") {
		t.Fatalf("unexpected result: %v", err)
	}
	if err := validateProcessResult(nil, result); err != nil {
		t.Fatal(err)
	}
}
