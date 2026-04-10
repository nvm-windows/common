package inspect

import "common/settings"

func InvalidTLS() *Check {
	fn := func(c *Check) error {
		cfg := settings.Global()

		if !cfg.DisableUpgrade {
			c.Warnings = []Problem{{
				Name:   "Insecure Downloads",
				Help:   "The computer's policy has disabled insecure TLS connections. Talk to your system administrator to enable insecure downloads.",
				Detail: "nvm cannot bypass invalid or expired TLS certificates using the --insecure flag when downloading Node.js.",
			}}
		}

		return nil
	}

	return &Check{
		Name:        "Bypass Invalid TLS",
		Description: "Checks for common issues that may prevent nvm from securely downloading Node.js versions.",
		fn:          fn,
	}
}
