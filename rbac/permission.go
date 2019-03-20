package rbac

import "strings"

type Permission interface {
	// Match shows whether uri matches the uri of Permission.
	Match(uri string) bool

	// Include shows whether an operation is included in the operation of Permission.
	Include(op operation) bool
}

type StandardPermission struct {
	Id        int64
	URI       string
	Operation operation
}

func (p *StandardPermission) Match(uri string) bool {
	if p.URI == uri {
		return true
	}

	if strings.Contains(p.URI, `/**`) {
		matcher := strings.ReplaceAll(p.URI, `/**`, ``)
		return strings.HasPrefix(uri, matcher)
	}

	if strings.Contains(p.URI, `/*`) {
		matcher := strings.ReplaceAll(p.URI, `/*`, ``)
		index := strings.LastIndex(uri, `/`)
		return uri[0:index] == matcher
	}
	return false
}

func (p *StandardPermission) Include(op operation) bool {
	return (p.Operation & op) == op
}
