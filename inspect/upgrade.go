package inspect

import "common/settings"

func Upgradability() *Check {
	fn := func(c *Check) error {
		cfg := settings.Global()

		if cfg.DisableUpgrade {
			c.Warnings = []Problem{{
				Name:   "Upgrades Disabled",
				Help:   "The computer's policy has disabled upgrading nvm. Talk to your system administrator to enable upgrades.",
				Detail: "This means nvm cannot manage its own upgrades. System administrators may still apply updates through other processes.",
			}}
		}

		return nil
	}

	return &Check{
		Name:        "Upgrade Capability",
		Description: "Checks for common issues that may prevent nvm from upgrading Node.js versions.",
		fn:          fn,
	}
}
