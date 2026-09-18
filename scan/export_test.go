package scan

// Test-only exports (all platforms): the glob engine behind Pattern, so the
// external scan_test package can exercise and fuzz it directly.

type Glob = glob

var CompileGlob = compileGlob

func (g *Glob) Match(comps []string) bool { return g.match(comps) }
