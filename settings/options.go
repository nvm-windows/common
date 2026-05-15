package settings

type Settings struct {
	Mode                         string   `cfg:"mode" reg:"OperatingMode" default:"shim" enum:"shim,link" help:"Specifies how Node.js commands and versions are managed, either through shim-based routing or direct junction/symlink linking."`
	Root                         string   `cfg:"root" reg:"InstallRoot" default:"%LOCALAPPDATA%\\Author Software\\nvm\\installs" help:"Root directory where Node.js versions are installed."`
	Proxy                        string   `cfg:"proxy" reg:"Proxy" help:"Proxy URL used to download assets." hidden:"true"`
	NodeMirror                   []string `cfg:"node_mirror" reg:"MirrorNode" default:"https://nodejs.org/dist" help:"Mirror URL(s) for downloading Node.js. Accepts a comma-delimited list."`
	NpmMirror                    []string `cfg:"npm_mirror" reg:"MirrorNpm" help:"Mirror URL(s) for downloading npm. Accepts a comma-delimited list." default:"https://registry.npmjs.org"`
	CacheDownloads               bool     `cfg:"cache_downloads" reg:"CacheDownloads" default:"false" help:"Whether to cache downloaded files for offline use."`
	ActiveVersion                string   `cfg:"active_version" reg:"ActiveVersion"`
	LastVersion                  string   `cfg:"last_version" reg:"PreviousActiveVersion" help:"The last active version before the current one. Used for 'nvm use last'." hidden:"true"`
	AutoDetect                   []string `cfg:"auto_detect" reg:"AutoDetect" default:".nvmrc,.node-version,package.json" help:"Project files to inspect for version (shim-only)."` // comma-separated list of files to inspect for version
	DefaultDetectFile            string   `cfg:"default_detect_file" reg:"DefaultDetectFile" default:".nvmrc" help:"The default file to write to when saving/pinning a version to a project."`
	AutoUse                      bool     `cfg:"auto_use" reg:"AutoUse" default:"true" help:"Automatically switch to auto-detected version to run the specified scripts without modifying the system version (shim-only)."`
	AutoInstall                  bool     `cfg:"auto_install" reg:"AutoInstall" default:"false" help:"Automatically install missing auto-detected version (rc/shim-only)."`
	AutoInstallPrompt            bool     `cfg:"auto_install_prompt" reg:"AutoInstallPrompt" default:"true" help:"Prompt before automatically installing missing auto-detected version (rc/shim-only)."`
	DisableUpgrade               bool     `cfg:"disable_upgrade" reg:"DisableUpgrade" default:"false" help:"Disable nvm upgrades." hidden:"true"`
	AllowInsecureDownloads       bool     `cfg:"allow_insecure_downloads" reg:"AllowInsecureDownloads" default:"false" help:"Allow expired/invalid SSL certificates when downloading assets." hidden:"false"`
	AllowDownloadCacheRemoval    bool     `cfg:"allow_download_cache_removal" reg:"AllowDownloadCacheDelete" default:"true" help:"Allow removing cached downloads."`
	AutoInstallModuleList        []string `cfg:"auto_installed_modules" reg:"AutoInstallModuleList" default:"" help:"Comma-delimited list of global npm modules to automatically install with new Node.js versions."`
	AllowRootDirChange           bool     `cfg:"allow_root_dir_change" reg:"AllowRootDirChange" default:"true" help:"Allow changing the install root directory." hidden:"true"`
	LocalInstallDir              string   `cfg:"local_dir" reg:"LocalInstallDir" help:"An alternative directory for installing Node.js versions. This overrides the cache." hidden:"true"`
	LocalInstallOnly             bool     `cfg:"local_install_only" reg:"LocalInstallOnly" default:"false" help:"Only install Node.js versions from the local install directory." hidden:"true"`
	NewsFeedURL                  string   `cfg:"news_feed_url" reg:"NewsFeedURL" default:"https://updates.nvm-windows.com/news" help:"URL for fetching news entries." hidden:"true"`
	LastUpdateCheck              string   `cfg:"last_update_check" reg:"LastUpdateCheck" help:"The last time updates were checked." hidden:"true"`
	LastNewsCheck                string   `cfg:"last_news_check" reg:"LastNewsCheck" help:"The last time news was checked." hidden:"true"`
	LastSyncCheck                string   `cfg:"last_sync_check" reg:"LastSyncCheck" help:"The last time sync app was updated." hidden:"true"`
	Aliases                      []string `cfg:"aliases" reg:"Aliases" default:"" help:"Comma-delimited list of version aliases in the format alias=version." hidden:"true"`
	AllowedSigners               []string `cfg:"allowed_signers" reg:"AllowedSigners" default:"Author Software Inc.,OpenJS Foundation,Node.js Foundation" help:"Comma-delimited list of allowed code signers." hidden:"true"`
	LogExecutions                bool     `cfg:"log_executions" reg:"LogExecutions" default:"false" help:"Whether to log every Node.js invocation (ex: node file.js). (shim-only)" hidden:"false"`
	Enabled                      bool     `cfg:"enabled" reg:"Enabled" default:"false" help:"Whether Node.js version management is enabled. This is automatically set when running 'nvm on' or 'nvm off'." hidden:"true"`
	AllowToolInstall             bool     `cfg:"allow_tool_install" reg:"AllowToolInstall" default:"true" help:"Whether to allow installation of native tools (nvm install native-tools)." hidden:"true"`
	DisableAnnouncements         bool     `cfg:"disable_announcements" reg:"DisableAnnouncements" default:"false" help:"Whether to disable project and release announcements." hidden:"false"`
	PackageManagerMismatchAction string   `cfg:"pm_mismatch_action" reg:"PackageManagerMismatchAction" default:"error" enum:"ignore,warn,error" help:"Action to take when a mismatch between npm and Node.js versions is detected during install or use: ignore, warn, or error."`
}
