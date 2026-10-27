package resolver

import "testing"

func TestFindExactVersionSkipsCatalog(t *testing.T) {
	for _, spec := range []string{"24.22.1", "v24.22.1", "24.22.1-rc.1"} {
		got, npm, err := Find(spec)
		if err != nil {
			t.Fatalf("Find(%q) error = %v", spec, err)
		}
		if got != "24.22.1" {
			t.Fatalf("Find(%q) = %q, want 24.22.1", spec, got)
		}
		if npm != "" {
			t.Fatalf("Find(%q) npm = %q, want empty (no catalog)", spec, npm)
		}
	}
}
