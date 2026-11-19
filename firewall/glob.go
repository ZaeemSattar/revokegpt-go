package firewall

import "strings"

// Glob is a compiled path glob: segments, each "**" (zero or more whole segments) or a
// segment pattern whose only metacharacter is "*".
type Glob struct {
	Source string
	// Canonical is the rule in canonical spelling (trailing slash dropped, literals through
	// decodeSegment).
	Canonical string
	segments  []globSegment
}

type globSegment struct {
	doubleStar bool
	pattern    string
}

// CompileGlob compiles a path glob, or returns nil if it is not valid (protocol v1, section
// 18.2). Grammar: starts with "/"; segments of literal characters and "*" (within one segment);
// a segment that is exactly "**" matches zero or more whole segments. At most 200 characters and
// 8 wildcards. Every literal piece goes through decodeSegment in glob mode, the same function
// that canonicalises request paths.
func CompileGlob(p string) *Glob {
	if len(p) == 0 || utf16Len(p) > maxGlobLength {
		return nil
	}
	if p[0] != '/' {
		return nil
	}
	body := p
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		body = p[:len(p)-1]
	}
	if body == "/" {
		return &Glob{Source: p, Canonical: "/"}
	}
	var segs []globSegment
	wildcards := 0
	canon := make([]string, 0, 8)
	for _, s := range strings.Split(body[1:], "/") {
		if s == "" {
			return nil
		}
		if s == "**" {
			wildcards++
			segs = append(segs, globSegment{doubleStar: true})
			canon = append(canon, "**")
			continue
		}
		if strings.Contains(s, "**") {
			return nil
		}
		pieces := strings.Split(s, "*")
		wildcards += len(pieces) - 1
		cp := make([]string, 0, len(pieces))
		for _, piece := range pieces {
			if piece == "" {
				cp = append(cp, "")
				continue
			}
			r := decodeSegment(piece, nonASCIIEncode)
			if !r.ok || strings.Contains(r.text, "*") {
				return nil
			}
			cp = append(cp, r.text)
		}
		seg := strings.Join(cp, "*")
		if seg == "." || seg == ".." {
			return nil
		}
		segs = append(segs, globSegment{pattern: seg})
		canon = append(canon, seg)
	}
	if wildcards > maxWildcards {
		return nil
	}
	return &Glob{Source: p, Canonical: "/" + strings.Join(canon, "/"), segments: segs}
}

// segmentMatches matches one segment against a pattern whose only metacharacter is "*".
func segmentMatches(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star = pi
			pi++
			mark = si
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// GlobMatch matches a normalised path (starting with "/") against a compiled glob. No recursion
// and no exponential case: one saved restart point for the last "**" and one inside a segment
// for the last "*"; the cost bound is O(N x P x L) as in the reference.
func GlobMatch(g *Glob, path string) bool {
	if g == nil || len(path) == 0 || path[0] != '/' {
		return false
	}
	var ps []string
	if path != "/" {
		ps = strings.Split(path[1:], "/")
	}
	segs := g.segments
	m, n := len(segs), len(ps)
	pi, si := 0, 0
	starP, starS := -1, 0
	for si < n {
		switch {
		case pi < m && segs[pi].doubleStar:
			starP = pi
			pi++
			starS = si
		case pi < m && segmentMatches(segs[pi].pattern, ps[si]):
			pi++
			si++
		case starP >= 0:
			pi = starP + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	for pi < m && segs[pi].doubleStar {
		pi++
	}
	return pi == m
}
