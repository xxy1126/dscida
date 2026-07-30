package cache

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/ipsw/pkg/dyld"
)

type Module struct {
	ImageIndex  uint32 `json:"image_index"`
	ModulePath  string `json:"module_path"`
	Basename    string `json:"basename"`
	LoadAddress string `json:"load_address"`
}

type Info struct {
	Path         string   `json:"path"`
	UUID         string   `json:"uuid"`
	Architecture string   `json:"architecture"`
	ImageCount   int      `json:"image_count"`
	Modules      []Module `json:"modules"`
}

func Open(path string) (*Info, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve DSC path: %w", err)
	}
	f, err := dyld.Open(absolute)
	if err != nil {
		return nil, fmt.Errorf("open DSC %q: %w", absolute, err)
	}
	defer f.Close()

	modules := make([]Module, 0, len(f.Images))
	for _, image := range f.Images {
		if image == nil || image.Name == "" {
			continue
		}
		modules = append(modules, Module{
			ImageIndex:  image.Index,
			ModulePath:  image.Name,
			Basename:    filepath.Base(image.Name),
			LoadAddress: fmt.Sprintf("0x%x", image.Info.Address),
		})
	}
	return &Info{
		Path:         absolute,
		UUID:         strings.ToUpper(f.UUID.String()),
		Architecture: architecture(absolute),
		ImageCount:   len(f.Images),
		Modules:      modules,
	}, nil
}

func architecture(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	header := make([]byte, 16)
	if _, err := reader.Read(header); err != nil {
		return "unknown"
	}
	magic := strings.TrimSpace(strings.TrimRight(string(header), "\x00"))
	if strings.HasPrefix(magic, "dyld_v1") {
		fields := strings.Fields(magic)
		if len(fields) > 1 {
			return fields[len(fields)-1]
		}
	}
	return "unknown"
}

func (i *Info) Exact(path string) (Module, error) {
	for _, module := range i.Modules {
		if module.ModulePath == path {
			return module, nil
		}
	}
	var suggestions []string
	query := strings.ToLower(filepath.Base(path))
	for _, module := range i.Modules {
		if strings.Contains(strings.ToLower(module.ModulePath), query) {
			suggestions = append(suggestions, module.ModulePath)
			if len(suggestions) == 8 {
				break
			}
		}
	}
	if len(suggestions) > 0 {
		return Module{}, fmt.Errorf("module not found: %s\n\nPossible matches:\n  %s", path, strings.Join(suggestions, "\n  "))
	}
	return Module{}, fmt.Errorf("module not found: %s", path)
}

func (i *Info) ByIndex(index int) (Module, bool) {
	for _, module := range i.Modules {
		if int(module.ImageIndex) == index {
			return module, true
		}
	}
	return Module{}, false
}

type Filter struct {
	Query      string
	Exact      string
	Offset     int
	Limit      int
	CacheOrder bool
}

func (i *Info) Filter(filter Filter) ([]Module, int) {
	var matches []Module
	for _, module := range i.Modules {
		if filter.Exact != "" && module.ModulePath != filter.Exact {
			continue
		}
		if filter.Query != "" && !strings.Contains(strings.ToLower(module.ModulePath), strings.ToLower(filter.Query)) {
			continue
		}
		matches = append(matches, module)
	}
	if !filter.CacheOrder {
		sort.Slice(matches, func(a, b int) bool {
			return matches[a].ModulePath < matches[b].ModulePath
		})
	}
	total := len(matches)
	offset := max(0, filter.Offset)
	if offset >= len(matches) {
		return []Module{}, total
	}
	matches = matches[offset:]
	if filter.Limit > 0 && filter.Limit < len(matches) {
		matches = matches[:filter.Limit]
	}
	return matches, total
}
