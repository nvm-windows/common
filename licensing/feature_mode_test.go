package license

import (
	"strings"
	"testing"
)

func TestInCommunityFeatureModeCertifiedWithoutToken(t *testing.T) {
	withBuildChannel(t, "certified")
	withEditionToken(t, "")

	if !InCommunityFeatureMode() {
		t.Fatal("expected community feature mode without token")
	}
	if !strings.Contains(CommunityFeatureModeWarning(), FeatureModeWarnCode) {
		t.Fatalf("warning missing code: %q", CommunityFeatureModeWarning())
	}
}

func TestInCommunityFeatureModeCertifiedWithCommercial(t *testing.T) {
	withBuildChannel(t, "certified")
	withEditionToken(t, mustMintAccessToken(t, "governance", false))

	if InCommunityFeatureMode() {
		t.Fatal("expected active commercial license")
	}
}

func TestInCommunityFeatureModeCommunityBuild(t *testing.T) {
	withBuildChannel(t, "community")
	withEditionToken(t, "")

	if InCommunityFeatureMode() {
		t.Fatal("community package is not community feature mode")
	}
}
