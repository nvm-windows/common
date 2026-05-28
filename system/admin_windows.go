package system

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func IsAdministrator() (bool, error) {
	token := windows.Token(0)
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("failed to verify administrator privileges: %w", err)
	}

	isAdmin, err := token.IsMember(adminSID)
	if err != nil {
		return false, fmt.Errorf("failed to verify administrator privileges: %w", err)
	}

	return isAdmin, nil
}

func RequireAdministrator() error {
	isAdmin, err := IsAdministrator()
	if err != nil {
		return err
	}
	if !isAdmin {
		return fmt.Errorf("this command must be run from an elevated administrator shell")
	}

	return nil
}
