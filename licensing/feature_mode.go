package license

import "fmt"

const (
	// FeatureModeWarnCode is the human-facing tag when a certified package runs
	// without an active commercial access token (community feature mode).
	FeatureModeWarnCode = "NVM4102"
	// FeatureModeWarnEventID is the classic Application log EventId for that advisory.
	FeatureModeWarnEventID = 4102
)

// InCommunityFeatureMode reports whether this is a certified package operating
// without an active commercial license. Community Inno builds never return true.
func InCommunityFeatureMode() bool {
	if IsCommunityBuild() {
		return false
	}
	_, ok := commercialLicenseType(accessTokenForEdition())
	return !ok
}

// CommunityFeatureModeWarning returns the stderr/event-log advisory for certified
// packages running without a valid commercial access token.
func CommunityFeatureModeWarning() string {
	return fmt.Sprintf(
		"%s: Missing/invalid license. Operating in community build mode.",
		FeatureModeWarnCode,
	)
}
