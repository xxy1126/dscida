package cache

import "testing"

func TestFilterPreservesImageIndex(t *testing.T) {
	info := &Info{Modules: []Module{
		{ImageIndex: 29, ModulePath: "/System/Library/Frameworks/Security.framework/Security"},
		{ImageIndex: 0, ModulePath: "/usr/lib/libobjc.A.dylib"},
	}}
	got, total := info.Filter(Filter{Query: "security"})
	if total != 1 || len(got) != 1 {
		t.Fatalf("unexpected result: total=%d modules=%v", total, got)
	}
	if got[0].ImageIndex != 29 {
		t.Fatalf("image index changed: %d", got[0].ImageIndex)
	}
}

func TestExactRejectsBasename(t *testing.T) {
	info := &Info{Modules: []Module{{
		ImageIndex: 29, ModulePath: "/System/Library/Frameworks/Security.framework/Security",
	}}}
	if _, err := info.Exact("Security"); err == nil {
		t.Fatal("basename unexpectedly resolved")
	}
}
