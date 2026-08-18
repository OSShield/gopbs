//go:build !linux

package scan

import "errors"

// DefaultReader returns the platform MetadataReader. Only Linux has one so
// far; other platforms must supply Options.Reader.
func DefaultReader() (MetadataReader, error) {
	return nil, errors.New("scan: no default MetadataReader for this platform (supply Options.Reader)")
}
