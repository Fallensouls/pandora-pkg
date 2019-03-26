package rbac

import (
	"strings"
)

type Permission interface {
	// Match shows whether uri matches the uri of Permission.
	Match(uri string) bool

	// Include shows whether an Operation is included in the Operation of Permission.
	Include(op Operation) bool
}

type StandardPermission struct {
	URI       string
	Operation Operation
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

func (p *StandardPermission) Include(op Operation) bool {
	return (p.Operation & op) == op
}

type Permissions interface {
	Load([]StandardPermission)
	HasPermission(uri string, op Operation) bool
	Destroy()
}

type PermissionList []StandardPermission

func NewPermissionList() *PermissionList {
	list := make(PermissionList, 0)
	return &list
}

func (l *PermissionList) Load(permissions []StandardPermission) {
	l.Destroy()
	*l = PermissionList(permissions)
	//for uri, op := range permissions {
	//	l.add(uri, op)
	//}
}

//func (l *PermissionList) add(uri string, op Operation) {
//	*l = append(*l, StandardPermission{uri, op})
//}

func (l *PermissionList) HasPermission(uri string, op Operation) (flag bool) {
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
	path      string
	operation Operation
	children  []*PermissionTree
}

func NewPermissionTree() (root *PermissionTree) {
	root = &PermissionTree{
		path:      ``,
		operation: Nil,
	}
	return
}

func (t *PermissionTree) Match(uri string) bool {
	paths := handleURI(uri)
search:
	for i, path := range paths {
		for _, child := range t.children {
			switch child.path {
			case `**`:
				return true
			case `*`:
				if i == len(paths)-1 {
					return true
				}
			default:
				if child.path == path {
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

func (t *PermissionTree) Include(op Operation) bool {
	return (t.operation & op) == op
}

func (t *PermissionTree) Load(permissions []StandardPermission) {
	t.Destroy()
	for _, permission := range permissions {
		t.add(permission.URI, permission.Operation)
	}
}

func (t *PermissionTree) add(uri string, op Operation) {
	paths := handleURI(uri)
insert:
	for j, path := range paths {
		for _, child := range t.children {
			if child.path == path {
				t = child
				if j == len(paths)-1 {
					child.operation = op
				}
				continue insert
			}
		}
		if j == len(paths)-1 {
			t.children = append(t.children, &PermissionTree{
				path:      path,
				operation: op,
			})
		} else {
			t.children = append(t.children, &PermissionTree{
				path:      path,
				operation: Nil,
			})
		}

		if len(t.children) > 0 {
			t = t.children[len(t.children)-1]
		} else {
			t = t.children[0]
		}
	}
}

func (t *PermissionTree) HasPermission(uri string, op Operation) bool {
	paths := handleURI(uri)
search:
	for i, path := range paths {
		for _, child := range t.children {
			switch child.path {
			case `**`:
				return child.Include(op)
			case `*`:
				if i == len(paths)-1 {
					return child.Include(op)
				}
			default:
				if child.path == path {
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
