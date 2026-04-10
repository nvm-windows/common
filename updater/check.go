package updater

import (
	"common/settings"
	"net/url"
)

type Release struct {
	URL             string `json:"url"`
	Version         string `json:"version"`
	ReleaseDate     string `json:"release_date"`
	ReleaseNotesURL string `json:"release_notes_url"`
}

// This method needs to read the CheckURL, caching the results (use the http.Download) to limit how often the download occurs. Once retrieved/loaded from cache, read the atom feed, compare the "updated" entry (a timestamp) to the settings.LastCheck date, and return a blank Release if the LastCheck is newer than the atom date (with a nil error). This indicates no updates are available. If the date is newer than the LastCheck, extract the first "entry" -> "title", which is the semver version, and select the first entry -> link[0] href, which is the release notes URL.

// If a release is available, use the GitHub API to retrieve the

func CheckForUpdates() (Release, error) {
	uri, err := url.Parse(settings.CheckURL)
	if err != nil {
		return Release{}, err
	}

}
