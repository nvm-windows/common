package fs

// InstallRootDeniedEvent is the stable event code for a blocked Node.js storage path.
const InstallRootDeniedEvent = "NVM4313"

// InstallRootDeniedMessage explains why a Node.js storage path is refused.
func InstallRootDeniedMessage() string {
	return "This path is not a safe Node.js storage location.\n" +
		"\n" +
		"Node.js versions must live in a dedicated directory. Uninstall removes that folder. " +
		"Storing versions in Windows, Program Files, your user profile, or other system folders can hide or delete other software.\n" +
		"\n" +
		"Disallowed locations include:\n" +
		"- Windows, System32, WinSxS, Program Files, Program Files (x86), ProgramData, WindowsApps, Recycle Bin\n" +
		"- Drive roots (C:\\)\n" +
		"- Your user profile, AppData, Desktop, Documents, Downloads, Pictures, Videos, Music\n" +
		"- Start Menu, Startup, LocalAppData\\Programs, LocalAppData\\Microsoft\n" +
		"- The NVM program folder, .shim, .nodejs, and utils\n" +
		"- Any parent of those folders (for example C:\\Users)\n" +
		"\n" +
		"Use a dedicated directory. Default: %LOCALAPPDATA%\\Author Software\\nvm\\installs\n" +
		"\n" +
		"Event code: " + InstallRootDeniedEvent
}
