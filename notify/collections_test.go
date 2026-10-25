package notify

import "testing"

func TestLiveCollectionsIDs(t *testing.T) {
	got := LiveCollections()
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	want := []string{CollectionReleases, CollectionHotfixes, CollectionPrereleases, CollectionNews}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("LiveCollections[%d].ID = %q, want %q", i, got[i].ID, id)
		}
		if got[i].Name == "" {
			t.Fatalf("LiveCollections[%d].Name empty", i)
		}
	}
}
