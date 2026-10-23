package notify

// Live toast collections (Windows Settings per-type mute).
// Assign a collection only when the user may mute that type.
const (
	CollectionReleases    = "nvm.releases"
	CollectionPrereleases = "nvm.prereleases"
	CollectionNews        = "nvm.news"
)

// Reserved collection ids — not registered this pass.
// Critical toasts (security, firewall, license, setup, activity) use the
// default notifier so Windows has no per-type mute. Uncomment registration
// in EnsureCollections and pass the id to SendTo/SendWithAudioTo to opt in.
const (
// CollectionSecurity = "nvm.security"
// CollectionFirewall = "nvm.firewall"
// CollectionLicense  = "nvm.license"
// CollectionSetup    = "nvm.setup"
// CollectionActivity = "nvm.activity"
)

// LiveCollections is the set SaveToastCollection registers.
func LiveCollections() []struct{ ID, Name string } {
	return []struct{ ID, Name string }{
		{CollectionReleases, "Releases"},
		{CollectionPrereleases, "Pre-releases"},
		{CollectionNews, "News"},
	}
}
