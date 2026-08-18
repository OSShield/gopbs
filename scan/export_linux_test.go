//go:build linux

package scan

// Test-only exports: compiled only for tests, keeping internals reachable
// from the external scan_test package without widening the public API.
var ParseACLXattr = parseACLXattr

const (
	ACLXattrVersion = aclVersion
	ACLTagUserObj   = aclTagUserObj
	ACLTagUser      = aclTagUser
	ACLTagGroupObj  = aclTagGroupObj
	ACLTagGroup     = aclTagGroup
	ACLTagMask      = aclTagMask
	ACLTagOther     = aclTagOther
)
