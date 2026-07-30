package binaryinput

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Identity struct {
	SourcePath   string `json:"source_path"`
	InputPath    string `json:"input_path"`
	SHA256       string `json:"input_sha256"`
	Size         int64  `json:"input_size"`
	Format       string `json:"binary_format"`
	Architecture string `json:"architecture"`
	IDAProcessor string `json:"ida_processor"`
	MachOUUID    string `json:"macho_uuid,omitempty"`
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func Stage(source, sessionDir string) (*Identity, error) {
	canonical, err := filepath.EvalSymlinks(source)
	if err != nil {
		return nil, fmt.Errorf("invalid_binary: resolve input: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return nil, err
	}
	input, err := openNoSymlink(canonical, false)
	if err != nil {
		return nil, fmt.Errorf("invalid_binary: open input: %w", err)
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid_binary: input is not a regular file")
	}
	inputDirectory, inputDir, err := secureInputDir(sessionDir)
	if err != nil {
		return nil, err
	}
	defer inputDirectory.Close()
	temporary, temporaryName, err := createTemporaryAt(inputDirectory)
	if err != nil {
		return nil, err
	}
	temporaryPath := filepath.Join(inputDir, temporaryName)
	keepTemporary := true
	defer func() {
		temporary.Close()
		if keepTemporary {
			_ = unix.Unlinkat(int(inputDirectory.Fd()), temporaryName, 0)
		}
	}()
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, hash), input)
	if copyErr != nil {
		return nil, fmt.Errorf("stage binary input: %w", copyErr)
	}
	if size != before.Size() {
		return nil, fmt.Errorf("input_changed_during_start: copied %d bytes, expected %d", size, before.Size())
	}
	if err := temporary.Sync(); err != nil {
		return nil, err
	}
	if err := temporary.Chmod(0o400); err != nil {
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	afterFD, err := input.Stat()
	if err != nil {
		return nil, err
	}
	afterPath, err := openNoSymlink(canonical, false)
	if err != nil {
		return nil, fmt.Errorf("input_changed_during_start: source path changed while staging")
	}
	afterPathInfo, pathStatErr := afterPath.Stat()
	afterPath.Close()
	if pathStatErr != nil || !sameFileIdentity(before, afterFD) || !sameFileIdentity(before, afterPathInfo) {
		return nil, fmt.Errorf("input_changed_during_start: source identity changed while staging")
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	format, architecture, processor, uuid, err := inspect(temporaryPath)
	if err != nil {
		return nil, err
	}
	name := unsafeName.ReplaceAllString(filepath.Base(canonical), "_")
	if name == "" || name == "." {
		name = "input"
	}
	finalName := sum + "__" + name
	finalPath := filepath.Join(inputDir, finalName)
	if err := unix.Linkat(int(inputDirectory.Fd()), temporaryName, int(inputDirectory.Fd()), finalName, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("publish immutable input: %w", err)
		}
		if err := verifyExistingAt(inputDirectory, finalName, sum, size); err != nil {
			return nil, err
		}
	}
	if err := unix.Unlinkat(int(inputDirectory.Fd()), temporaryName, 0); err != nil {
		return nil, err
	}
	keepTemporary = false
	if err := inputDirectory.Sync(); err != nil {
		return nil, err
	}
	return &Identity{
		SourcePath: canonical, InputPath: finalPath, SHA256: sum, Size: size,
		Format: format, Architecture: architecture, MachOUUID: uuid,
		IDAProcessor: processor,
	}, nil
}

func Verify(identity Identity) error {
	source, err := filepath.EvalSymlinks(identity.SourcePath)
	if err != nil {
		return fmt.Errorf("binary_identity_mismatch: resolve source: %w", err)
	}
	source, _ = filepath.Abs(source)
	if source != identity.SourcePath {
		return fmt.Errorf("binary_identity_mismatch: source path changed")
	}
	sourceFile, err := openNoSymlink(source, false)
	if err != nil {
		return fmt.Errorf("binary_identity_mismatch: %w", err)
	}
	sum, size, err := hashOpenFile(sourceFile)
	sourceFile.Close()
	if err != nil {
		return fmt.Errorf("binary_identity_mismatch: %w", err)
	}
	if sum != identity.SHA256 || size != identity.Size {
		return fmt.Errorf("binary_identity_mismatch: source content changed")
	}
	staged, err := openNoSymlink(identity.InputPath, false)
	if err != nil {
		return fmt.Errorf("binary_identity_mismatch: staged input: %w", err)
	}
	if err := verifyOpenFile(staged, identity.SHA256, identity.Size); err != nil {
		staged.Close()
		return fmt.Errorf("binary_identity_mismatch: staged input: %w", err)
	}
	staged.Close()
	return nil
}

func inspect(path string) (format, architecture, processor, uuid string, err error) {
	header, headerErr := os.Open(path)
	if headerErr != nil {
		return "", "", "", "", headerErr
	}
	var magic [4]byte
	_, _ = io.ReadFull(header, magic[:])
	header.Close()
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return "", "", "", "", fmt.Errorf("ambiguous_binary_architecture: fat Mach-O is not supported")
	}
	if fat, fatErr := macho.OpenFat(path); fatErr == nil {
		fat.Close()
		return "", "", "", "", fmt.Errorf("ambiguous_binary_architecture: fat Mach-O is not supported")
	}
	if file, machoErr := macho.Open(path); machoErr == nil {
		defer file.Close()
		switch file.Type {
		case macho.TypeObj, macho.TypeExec, macho.TypeDylib, macho.TypeBundle, macho.Type(11):
		default:
			return "", "", "", "", fmt.Errorf("unsupported_binary_format: unsupported Mach-O file type %s", file.Type)
		}
		switch file.Cpu {
		case macho.Cpu386, macho.CpuAmd64, macho.CpuArm, macho.CpuArm64:
		default:
			return "", "", "", "", fmt.Errorf("unsupported_architecture: unsupported Mach-O CPU %s", file.Cpu)
		}
		for _, load := range file.Loads {
			raw := load.Raw()
			if len(raw) < 8 {
				continue
			}
			command := file.ByteOrder.Uint32(raw[:4])
			switch command {
			case 0x21, 0x2c: // LC_ENCRYPTION_INFO(_64)
				if len(raw) >= 20 && file.ByteOrder.Uint32(raw[16:20]) != 0 {
					return "", "", "", "", fmt.Errorf("unsupported_binary_format: encrypted Mach-O is not supported")
				}
			case 0x1b: // LC_UUID
				if len(raw) >= 24 {
					uuid = formatUUID(raw[8:24])
				}
			}
		}
		processor = processorForMachO(file.Cpu)
		return "macho", file.Cpu.String(), processor, uuid, nil
	}
	file, elfErr := elf.Open(path)
	if elfErr != nil {
		return "", "", "", "", fmt.Errorf("unsupported_binary_format: input is neither a supported thin Mach-O nor ELF")
	}
	defer file.Close()
	if file.Data != elf.ELFDATA2LSB {
		return "", "", "", "", fmt.Errorf("unsupported_binary_format: big-endian ELF is not supported")
	}
	switch file.Type {
	case elf.ET_REL, elf.ET_EXEC, elf.ET_DYN:
	default:
		return "", "", "", "", fmt.Errorf("unsupported_binary_format: unsupported ELF type %s", file.Type)
	}
	if file.Class != elf.ELFCLASS32 && file.Class != elf.ELFCLASS64 {
		return "", "", "", "", fmt.Errorf("unsupported_binary_format: unsupported ELF class %s", file.Class)
	}
	switch file.Machine {
	case elf.EM_386, elf.EM_X86_64, elf.EM_ARM, elf.EM_AARCH64:
	default:
		return "", "", "", "", fmt.Errorf("unsupported_architecture: unsupported ELF machine %s", file.Machine)
	}
	return "elf", strings.ToLower(file.Machine.String()), processorForELF(file.Machine), "", nil
}

func processorForMachO(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386, macho.CpuAmd64:
		return "pc"
	default:
		return "arm"
	}
}

func processorForELF(machine elf.Machine) string {
	switch machine {
	case elf.EM_386, elf.EM_X86_64:
		return "pc"
	default:
		return "arm"
	}
}

func formatUUID(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	// UUID byte order is already canonical in LC_UUID.
	encoded := hex.EncodeToString(value)
	return strings.ToUpper(encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32])
}

func verifyExistingAt(directory *os.File, name, expected string, size int64) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return verifyOpenFile(file, expected, size)
}

func verifyOpenFile(file *os.File, expected string, size int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Size() != size {
		return fmt.Errorf("immutable input has unexpected type, mode, or size")
	}
	sum, actualSize, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if sum != expected || actualSize != size {
		return fmt.Errorf("immutable input SHA256 mismatch")
	}
	return nil
}

func hashOpenFile(file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func sameFileIdentity(left, right os.FileInfo) bool {
	if left == nil || right == nil || left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	lstat, lok := left.Sys().(*syscall.Stat_t)
	rstat, rok := right.Sys().(*syscall.Stat_t)
	return !lok || !rok || (lstat.Dev == rstat.Dev && lstat.Ino == rstat.Ino)
}

func secureInputDir(sessionDir string) (*os.File, string, error) {
	if err := os.MkdirAll(filepath.Dir(sessionDir), 0o700); err != nil {
		return nil, "", err
	}
	if info, err := os.Lstat(sessionDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, "", fmt.Errorf("binary input session path is not a trusted directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(sessionDir, 0o700); err != nil {
			return nil, "", err
		}
	} else {
		return nil, "", err
	}
	if err := os.Chmod(sessionDir, 0o700); err != nil {
		return nil, "", err
	}
	canonicalSession, err := filepath.EvalSymlinks(sessionDir)
	if err != nil {
		return nil, "", err
	}
	sessionDirectory, err := openNoSymlink(canonicalSession, true)
	if err != nil {
		return nil, "", err
	}
	sessionInfo, err := sessionDirectory.Stat()
	sessionDirectory.Close()
	if err != nil {
		return nil, "", err
	}
	sessionStat, ok := sessionInfo.Sys().(*syscall.Stat_t)
	if !ok || int(sessionStat.Uid) != os.Getuid() || sessionInfo.Mode().Perm() != 0o700 {
		return nil, "", fmt.Errorf("binary session directory has unexpected owner or permissions")
	}
	inputDir := filepath.Join(canonicalSession, "inputs")
	if info, err := os.Lstat(inputDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, "", fmt.Errorf("binary input directory is not a trusted directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(inputDir, 0o700); err != nil {
			return nil, "", err
		}
	} else {
		return nil, "", err
	}
	if err := os.Chmod(inputDir, 0o700); err != nil {
		return nil, "", err
	}
	dir, err := openNoSymlink(inputDir, true)
	if err != nil {
		return nil, "", err
	}
	info, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm() != 0o700 {
		dir.Close()
		return nil, "", fmt.Errorf("binary input directory has unexpected owner or permissions")
	}
	return dir, inputDir, nil
}

func createTemporaryAt(directory *os.File) (*os.File, string, error) {
	for attempts := 0; attempts < 100; attempts++ {
		var random [12]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".staging-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(
			int(directory.Fd()), name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			return os.NewFile(uintptr(fd), filepath.Join(directory.Name(), name)), name, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("create staging input: exhausted unique names")
}

func openNoSymlink(path string, directory bool) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("path must be absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return nil, fmt.Errorf("invalid path component")
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), clean), nil
}
