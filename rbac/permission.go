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

type Permissions interface {
	HasPermission(uri string, op operation) bool
}

type PermissionList []StandardPermission

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

type PermissionTree struct {
	Path      string
	Operation operation
	Children  []*PermissionTree
}

func (t *PermissionTree) Match(uri string) bool {
	return t.Path == uri
}

func (t *PermissionTree) Include(op operation) bool {
	return (t.Operation & op) == op
}

func (t *PermissionTree) HasPermission(uri string, op operation) bool {
	paths := strings.Split(uri, `/`)
	tree := t
search:
	for i, path := range paths {
		for _, child := range tree.Children {
			if child.Match(path) {
				if i == len(paths)-1 {
					return child.Include(op)
				}
				tree = child
				continue search
			}
		}
		break
	}
	return false
}

func (t *PermissionTree) Destroy() {
	t = &PermissionTree{}
}

func (t *PermissionTree) Insert(uri string, op operation) {
	paths := strings.Split(uri, `/`)
	tree := t

insert:
	for j, path := range paths {
		for _, child := range tree.Children {
			if child.Path == path {
				tree = child
				if j == len(paths)-1 {
					child.Operation = op
				}
				continue insert
			}
		}
		if j == len(paths)-1 {
			tree.Children = append(tree.Children, &PermissionTree{
				Path:      path,
				Operation: op,
			})
		} else {
			tree.Children = append(tree.Children, &PermissionTree{
				Path:      path,
				Operation: 0,
			})
		}

		if len(tree.Children) > 0 {
			tree = tree.Children[len(tree.Children)-1]
		} else {
			tree = tree.Children[0]
		}
	}
}

func Convert(list PermissionList) (root *PermissionTree) {
	root = &PermissionTree{
		Path:      `/`,
		Operation: 0,
	}
	for _, permission := range list {
		root.Insert(permission.URI, permission.Operation)
	}
	return
}
