package catalog

// Test-only exports: compiled only for tests, keeping internals reachable
// from the external catalog_test package without widening the public API.
var (
	AppendU64 = appendU64
	AppendI64 = appendI64
	DecodeU64 = decodeU64
	DecodeI64 = decodeI64
)
