package notify

import "testing"

func TestLiveCollectionsIDs(t *testing.T) {
	got := LiveCollections()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []string{CollectionReleases, CollectionPrereleases, CollectionNews}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("LiveCollections[%d].ID = %q, want %q", i, got[i].ID, id)
		}
		if got[i].Name == "" {
			t.Fatalf("LiveCollections[%d].Name empty", i)
		}
	}
}
