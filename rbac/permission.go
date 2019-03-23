package rbac

import (
	"strings"
)

type Permission interface {
	// Match shows whether uri matches the uri of Permission.
	Match(uri string) bool

	// Include shows whether an operation is included in the operation of Permission.
	Include(op operation) bool
}

type StandardPermission struct {
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

type Permissions interface {
	Add(uri string, op operation)
	HasPermission(uri string, op operation) bool
	Destroy()
}

type PermissionList []StandardPermission

func NewList(permissions map[string]operation) *PermissionList {
	list := make(PermissionList, 0)
	for uri, op := range permissions {
		list.Add(uri, op)
	}
	return &list
}

func (l *PermissionList) Add(uri string, op operation) {
	*l = append(*l, StandardPermission{uri, op})
}

func (l *PermissionList) HasPermission(uri string, op operation) (flag bool) {
	for _, permission := range *l {
		if !permission.Match(uri) {
			continue
		}
		if permission.Include(op) {
			flag = true
			break
		}
	}
	return
}

func (l *PermissionList) Destroy() {
	*l = PermissionList{}
}

type PermissionTree struct {
	Path      string
	Operation operation
	Children  []*PermissionTree
}

func NewTree(permissions PermissionList) (root *PermissionTree) {
	root = &PermissionTree{
		Path:      ``,
		Operation: Nil,
	}
	for _, permission := range permissions {
		root.Add(permission.URI, permission.Operation)
	}
	return
}

func (t *PermissionTree) Match(uri string) bool {
	paths := handleURI(uri)
search:
	for i, path := range paths {
		for _, child := range t.Children {
			switch child.Path {
			case `**`:
				return true
			case `*`:
				if i == len(paths)-1 {
					return true
				}
			default:
				if child.Path == path {
					if i == len(paths)-1 {
						return true
					}
					t = child
					continue search
				}
			}
		}
		break
	}
	return false
}

func (t *PermissionTree) Include(op operation) bool {
	return (t.Operation & op) == op
}

func (t *PermissionTree) Add(uri string, op operation) {
	paths := handleURI(uri)
insert:
	for j, path := range paths {
		for _, child := range t.Children {
			if child.Path == path {
				t = child
				if j == len(paths)-1 {
					child.Operation = op
				}
				continue insert
			}
		}
		if j == len(paths)-1 {
			t.Children = append(t.Children, &PermissionTree{
				Path:      path,
				Operation: op,
			})
		} else {
			t.Children = append(t.Children, &PermissionTree{
				Path:      path,
				Operation: Nil,
			})
		}

		if len(t.Children) > 0 {
			t = t.Children[len(t.Children)-1]
		} else {
			t = t.Children[0]
		}
	}
}

func (t *PermissionTree) HasPermission(uri string, op operation) bool {
	paths := handleURI(uri)
search:
	for i, path := range paths {
		for _, child := range t.Children {
			switch child.Path {
			case `**`:
				return child.Include(op)
			case `*`:
				if i == len(paths)-1 {
					return child.Include(op)
				}
			default:
				if child.Path == path {
					if i == len(paths)-1 {
						return child.Include(op)
					}
					t = child
					continue search
				}
			}
		}
		break
	}
	return false
}

func (t *PermissionTree) Destroy() {
	*t = PermissionTree{}
}

func handleURI(uri string) []string {
	paths := strings.Split(uri, `/`)
	if paths[0] == "" {
		paths = paths[1:]
	}
	if paths[len(paths)-1] == "" {
		paths = paths[:len(paths)-1]
	}
	return paths
}
