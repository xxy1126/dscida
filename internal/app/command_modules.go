package app

import (
	"fmt"
	"text/tabwriter"

	"github.com/tmo/dscida/internal/cache"
)

func (e *environment) modules(args []string) error {
	set := flagSet("modules", e.stderr)
	query := set.String("query", "", "case-insensitive full-path substring")
	exact := set.String("exact", "", "exact canonical module path")
	offset := set.Int("offset", 0, "skip matching entries")
	limit := set.Int("limit", 0, "maximum results; 0 means all")
	long := set.Bool("long", false, "show details")
	jsonOutput := set.Bool("json", false, "emit JSON")
	cacheOrder := set.Bool("cache-order", false, "preserve DSC image order")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida modules <DSC> [flags]"); err != nil {
		return err
	}
	if *offset < 0 || *limit < 0 {
		return fmt.Errorf("offset and limit must be non-negative")
	}
	info, err := cache.Open(set.Arg(0))
	if err != nil {
		return err
	}
	modules, total := info.Filter(cache.Filter{
		Query: *query, Exact: *exact, Offset: *offset, Limit: *limit, CacheOrder: *cacheOrder,
	})
	if *jsonOutput {
		return writeJSON(e.stdout, map[string]any{
			"dsc": map[string]any{
				"path": info.Path, "uuid": info.UUID, "architecture": info.Architecture,
			},
			"total_matches": total, "returned_count": len(modules),
			"offset": *offset, "limit": *limit, "modules": modules,
		})
	}
	if *long {
		table := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(table, "IMAGE_INDEX\tLOAD_ADDRESS\tMODULE_PATH")
		for _, module := range modules {
			fmt.Fprintf(table, "%d\t%s\t%s\n", module.ImageIndex, module.LoadAddress, module.ModulePath)
		}
		return table.Flush()
	}
	for _, module := range modules {
		fmt.Fprintln(e.stdout, module.ModulePath)
	}
	return nil
}
