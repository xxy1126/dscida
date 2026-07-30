package binaryinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageAndVerifyELF(t *testing.T) {
	source := "/bin/ls"
	if _, err := os.Stat(source); err != nil {
		t.Skip("ELF fixture unavailable")
	}
	// This test is portable only when /bin/ls is ELF (for example Linux CI).
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	var magic [4]byte
	_, _ = file.Read(magic[:])
	file.Close()
	if string(magic[:]) != "\x7fELF" {
		t.Skip("/bin/ls is not ELF on this host")
	}
	identity, err := Stage(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Format != "elf" || len(identity.SHA256) != 64 {
		t.Fatalf("identity=%+v", identity)
	}
	info, err := os.Stat(identity.InputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("immutable input mode=%o", info.Mode().Perm())
	}
	if err := Verify(*identity); err != nil {
		t.Fatal(err)
	}
}

func TestStageRejectsUnknownInput(t *testing.T) {
	source := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(source, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Stage(source, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsupported_binary_format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenNoSymlinkRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openNoSymlink(link, false); err == nil {
		file.Close()
		t.Fatal("symlink input unexpectedly opened")
	}
}

func TestSecureInputDirRejectsSessionSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	session := filepath.Join(root, "session")
	if err := os.Symlink(outside, session); err != nil {
		t.Fatal(err)
	}
	if directory, _, err := secureInputDir(session); err == nil {
		directory.Close()
		t.Fatal("symlinked session directory unexpectedly accepted")
	}
}

func TestInspectClassifiesAllFatMagicsAsAmbiguous(t *testing.T) {
	for _, magic := range [][]byte{
		{0xca, 0xfe, 0xba, 0xbe},
		{0xbe, 0xba, 0xfe, 0xca},
		{0xca, 0xfe, 0xba, 0xbf},
		{0xbf, 0xba, 0xfe, 0xca},
	} {
		path := filepath.Join(t.TempDir(), "fat")
		if err := os.WriteFile(path, magic, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, _, _, err := inspect(path)
		if err == nil || !strings.Contains(err.Error(), "ambiguous_binary_architecture") {
			t.Fatalf("magic %x produced %v", magic, err)
		}
	}
}
