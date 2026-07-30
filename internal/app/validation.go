package app

import (
	"fmt"
	"sort"

	"github.com/tmo/dscida/internal/cache"
	"github.com/tmo/dscida/internal/store"
)

func validateLoadedIndexes(indexes []int, imageCount, primary int) error {
	seen := make(map[int]bool, len(indexes))
	found := false
	for _, index := range indexes {
		if index < 0 || index >= imageCount {
			return fmt.Errorf("DSCU loaded-image backend returned out-of-bounds index %d", index)
		}
		if seen[index] {
			return fmt.Errorf("DSCU loaded-image backend returned duplicate index %d", index)
		}
		seen[index] = true
		if index == primary {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("unsupported_dscu_state_backend: primary image index %d not reported (got %v)", primary, indexes)
	}
	return nil
}

func expectedIndexes(session *store.Session, job *store.Job) ([]int, error) {
	expected := append([]int(nil), session.LoadedImageIndexes...)
	if job.Operation == "add" {
		if job.ImageIndex == nil {
			return nil, fmt.Errorf("add job has no image index")
		}
		if *job.ImageIndex < 0 || *job.ImageIndex >= session.ImageCount {
			return nil, fmt.Errorf("add image index %d is outside cache bounds", *job.ImageIndex)
		}
		found := false
		for _, index := range expected {
			if index == *job.ImageIndex {
				found = true
				break
			}
		}
		if !found {
			expected = append(expected, *job.ImageIndex)
		}
	}
	sort.Ints(expected)
	for index, value := range expected {
		if value < 0 || value >= session.ImageCount {
			return nil, fmt.Errorf("expected image index %d is outside cache bounds", value)
		}
		if index > 0 && expected[index-1] == value {
			return nil, fmt.Errorf("duplicate expected image index %d", value)
		}
	}
	return expected, nil
}

func sameIndexes(observed, expected []int) bool {
	if len(observed) != len(expected) {
		return false
	}
	left := append([]int(nil), observed...)
	right := append([]int(nil), expected...)
	sort.Ints(left)
	sort.Ints(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateObservedIndexes(observed, required []int, imageCount int) ([]int, error) {
	result := append([]int(nil), observed...)
	sort.Ints(result)
	for index, value := range result {
		if value < 0 || value >= imageCount {
			return nil, fmt.Errorf("sidecar reported out-of-bounds loaded image index %d", value)
		}
		if index > 0 && result[index-1] == value {
			return nil, fmt.Errorf("sidecar reported duplicate loaded image index %d", value)
		}
	}
	for _, requiredIndex := range required {
		position := sort.SearchInts(result, requiredIndex)
		if position >= len(result) || result[position] != requiredIndex {
			return nil, fmt.Errorf(
				"sidecar loaded indexes %v lost required image index %d",
				observed, requiredIndex,
			)
		}
	}
	return result, nil
}

func reconcileModules(session *store.Session, info *cache.Info) {
	requested := make(map[string]bool, len(session.LoadedModules))
	for _, module := range session.LoadedModules {
		requested[module] = true
	}
	var implicit []string
	for _, index := range session.LoadedImageIndexes {
		module, ok := info.ByIndex(index)
		if ok && !requested[module.ModulePath] {
			implicit = append(implicit, module.ModulePath)
		}
	}
	sort.Strings(implicit)
	session.ImplicitlyLoaded = implicit
}
