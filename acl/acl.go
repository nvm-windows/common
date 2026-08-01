package acl

// Implementation identifies which ACL module is linked.
// "stub" = OSS/community no-op; "policy" = certified version allow/block lists.
func Implementation() string {
	return "stub"
}

func IsAllowedVersion(version string) (bool, error) {
	return true, nil
}
