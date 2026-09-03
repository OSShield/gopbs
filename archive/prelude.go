package archive

import "strconv"

// preludeJSON wraps the .pxarexclude-cli content the way proxmox-backup-client
// serializes its v2 prelude: the JSON object {"exclude-patterns":"…"} with
// serde_json's compact string escaping (only '"', '\\' and control
// characters are escaped; \b \f \n \r \t short, the rest \u00xx).
func preludeJSON(patterns []byte) []byte {
	out := make([]byte, 0, len(patterns)+32)
	out = append(out, `{"exclude-patterns":"`...)
	for _, c := range patterns {
		switch c {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0')
				out = append(out, strconv.FormatUint(uint64(c>>4), 16)...)
				out = append(out, strconv.FormatUint(uint64(c&0xf), 16)...)
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, `"}`...)
}
