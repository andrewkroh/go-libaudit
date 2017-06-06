package rule

import "fmt"

// Type specifies the audit rule type.
type Type int

const (
	DeleteAllRuleType      Type = iota + 1 // DeleteAllRule
	FileWatchRuleType                      // FileWatchRule
	AppendSyscallRuleType                  // SyscallRule
	PrependSyscallRuleType                 // SyscallRule
)

type Rule interface {
	TypeOf() Type // TypeOf returns the type of rule.
}

type DeleteAllRule struct {
	Type Type
	Keys []string
}

func (r *DeleteAllRule) TypeOf() Type { return r.Type }

type FileWatchRule struct {
	Type        Type
	Path        string
	Permissions []AccessType
	Keys        []string
}

func (r *FileWatchRule) TypeOf() Type { return r.Type }

type SyscallRule struct {
	Type     Type
	List     string
	Action   string
	Filters  []FilterSpec
	Syscalls []string
	Keys     []string
}

func (r *SyscallRule) TypeOf() Type { return r.Type }

type AccessType uint8

const (
	ReadAccessType AccessType = iota + 1
	WriteAccessType
	ExecuteAccessType
	AttributeChangeAccessType
)

var accessTypeName = map[AccessType]string{
	ReadAccessType:            "read",
	WriteAccessType:           "write",
	ExecuteAccessType:         "execute",
	AttributeChangeAccessType: "attribute",
}

func (t AccessType) String() string {
	name, found := accessTypeName[t]
	if found {
		return name
	}
	return "unknown"
}

type FilterType uint8

const (
	InterFieldFilterType FilterType = iota + 1 // Inter-field comparison filtering (-C).
	ValueFilterType                            // Filtering based on values (-F).
)

type FilterSpec struct {
	Type       FilterType
	LHS        string
	Comparator string
	RHS        string
}

func (f *FilterSpec) String() string {
	return fmt.Sprintf("%v %v %v", f.LHS, f.Comparator, f.RHS)
}
