package rbac

type Policies interface {
	// Load should load all policies for authorization.
	Load([]StandardPolicy)

	// Require determines whether a request needs authorization and returns all roles that have the permission.
	Require(uri string, op Operation) ([]int64, bool)

	// Destroy should clean up all policies and return an empty struct.
	Destroy()
}

type StandardPolicy struct {
	URI    string
	Groups []PermissionGroup
}

type PermissionGroup struct {
	Operation Operation
	RoleID    []int64
}

func (g *PermissionGroup) collectRoleID(op Operation, roleID *[]int64) {
	if g.include(op) {
		*roleID = append(*roleID, g.RoleID...)
	}
}

func (g *PermissionGroup) include(op Operation) bool {
	return (g.Operation & op) == op
}

type PolicyTree struct {
	path     string
	groups   []PermissionGroup
	children []*PolicyTree
}

func NewPolicyTree() *PolicyTree {
	root := PolicyTree{
		path: ``,
	}
	return &root
}

func (t *PolicyTree) Load(policies []StandardPolicy) {
	t.Destroy()
	for _, policy := range policies {
		t.add(policy.URI, policy.Groups)
	}
}

func (t *PolicyTree) Require(uri string, op Operation) ([]int64, bool) {
	paths := handleURI(uri)
	roleID := make([]int64, 0)
search:
	for i, path := range paths {
		for _, child := range t.children {
			switch child.path {
			case `**`:
				for _, group := range child.groups {
					group.collectRoleID(op, &roleID)
				}
				if len(roleID) != 0 {
					return roleID, true
				}
			case `*`:
				if i == len(paths)-1 {
					for _, group := range child.groups {
						group.collectRoleID(op, &roleID)
					}
					if len(roleID) != 0 {
						return roleID, true
					}
				}
			default:
				if child.path == path {
					if i == len(paths)-1 {
						for _, group := range child.groups {
							group.collectRoleID(op, &roleID)
						}
						if len(roleID) != 0 {
							return roleID, true
						}
					}
					t = child
					continue search
				}
			}
		}
		break
	}
	return nil, false
}

func (t *PolicyTree) Destroy() {
	*t = PolicyTree{}
}

func (t *PolicyTree) add(uri string, group []PermissionGroup) {
	paths := handleURI(uri)
insert:
	for j, path := range paths {
		for _, child := range t.children {
			if child.path == path {
				t = child
				if j == len(paths)-1 {
					child.groups = group
				}
				continue insert
			}
		}
		if j == len(paths)-1 {
			t.children = append(t.children, &PolicyTree{
				path:   path,
				groups: group,
			})
		} else {
			t.children = append(t.children, &PolicyTree{
				path: path,
			})
		}

		if len(t.children) > 0 {
			t = t.children[len(t.children)-1]
		} else {
			t = t.children[0]
		}
	}
}
