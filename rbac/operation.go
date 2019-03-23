package rbac

type operation uint8

const (
	Nil    operation = 0
	Create operation = 1 << iota
	Read
	Update
	Delete
)

const (
	CR   = Create | Read
	RU   = Read | Update
	RD   = Read | Delete
	CRU  = Create | Read | Update
	RUD  = Read | Update | Delete
	CRUD = Create | Read | Update | Delete
)
