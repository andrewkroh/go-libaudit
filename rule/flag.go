package rule

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

// StringList is a flag type for usage when the parameter has an arity > 1.
type StringList []string

func (l *StringList) String() string {
	return "[" + strings.Join(*l, ", ") + "]"
}

func (l *StringList) Set(value string) error {
	words := strings.Split(value, ",")
	for _, w := range words {
		*l = append(*l, strings.TrimSpace(w))
	}
	return nil
}

// AddFlag is a flag type for appending or prepending a rule.
type AddFlag struct {
	List   string
	Action string
}

func (f *AddFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) > 2 {
		return fmt.Errorf("expected a list type and action but got '%v'", value)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "task", "exit", "user", "exclude":
			f.List = part
		case "never", "always":
			f.Action = part
		default:
			return fmt.Errorf("invalid list type or action: '%v'", part)
		}
	}

	if f.List == "" {
		return errors.New("missing list type")
	}
	if f.Action == "" {
		return errors.New("missing action")
	}
	return nil
}

func (f *AddFlag) String() string {
	return fmt.Sprintf("%v,%v", f.List, f.Action)
}

type ComparisonFlag struct {
	LHS        string
	Comparator string
	RHS        string
}

var comparisonRegexp = regexp.MustCompile(`(\w+)\s*(!?=)(\w+)`)

func (f *ComparisonFlag) Set(value string) error {
	values := comparisonRegexp.FindStringSubmatch(value)
	if len(values) != 4 {
		return fmt.Errorf("invalid comparison: '%v'", value)
	}

	f.LHS = values[1]
	f.Comparator = values[2]
	f.RHS = values[3]
	return nil
}

func (f *ComparisonFlag) String() string {
	return fmt.Sprintf("%v %v %v", f.LHS, f.Comparator, f.RHS)
}

type ComparisonFlagList []ComparisonFlag

func (l *ComparisonFlagList) Set(value string) error {
	comparisonFlag := &ComparisonFlag{}
	if err := comparisonFlag.Set(value); err != nil {
		return err
	}
	*l = append(*l, *comparisonFlag)
	return nil
}

func (l *ComparisonFlagList) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("[")
	for i, v := range *l {
		buf.WriteString(v.String())
		if i > len(*l)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString("]")
	return buf.String()
}

type FilterFlag struct {
	LHS        string
	Comparator string
	RHS        string
}

var filterRegexp = regexp.MustCompile(`(\S+)\s*(=|!=|<|>|<=|>=|&|&=)(\S+)`)

func (f *FilterFlag) Set(value string) error {
	values := filterRegexp.FindStringSubmatch(value)
	if len(values) != 4 {
		return fmt.Errorf("invalid filter: '%v'", value)
	}

	f.LHS = values[1]
	f.Comparator = values[2]
	f.RHS = values[3]
	return nil
}

func (f *FilterFlag) String() string {
	return fmt.Sprintf("%v %v %v", f.LHS, f.Comparator, f.RHS)
}

type FilterFlagList []FilterFlag

func (l *FilterFlagList) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("[")
	for i, v := range *l {
		buf.WriteString(v.String())
		if i > len(*l)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString("]")
	return buf.String()
}

func (l *FilterFlagList) Set(value string) error {
	filterFlag := &FilterFlag{}
	if err := filterFlag.Set(value); err != nil {
		return err
	}
	*l = append(*l, *filterFlag)
	return nil
}

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

type FileAccessTypeFlag struct {
	Flags []AccessType
}

func (f *FileAccessTypeFlag) Set(value string) error {
	for _, v := range []byte(value) {
		switch v {
		case 'r':
			f.Flags = append(f.Flags, ReadAccessType)
		case 'w':
			f.Flags = append(f.Flags, WriteAccessType)
		case 'x':
			f.Flags = append(f.Flags, ExecuteAccessType)
		case 'a':
			f.Flags = append(f.Flags, AttributeChangeAccessType)
		default:
			return fmt.Errorf("invalid file access type: '%v'", string(v))
		}
	}
	return nil
}

func (f *FileAccessTypeFlag) String() string {
	flags := make([]string, 0, len(f.Flags))
	for _, accessType := range f.Flags {
		flags = append(flags, accessType.String())
	}
	return "[" + strings.Join(flags, "|") + "]"
}

type RuleType int

const (
	DeleteAllRuleType RuleType = iota + 1
	FileWatchRuleType
	AppendSyscallRuleType
	PrependSyscallRuleType
)

type RuleFlagSet struct {
	Type RuleType

	DeleteAll bool // [-D] Delete all rules.

	// Audit Rule
	Prepend    AddFlag            // -A Prepend rule (list,action) or (action,list).
	Append     AddFlag            // -a Append rule (list,action) or (action,list).
	Comparison ComparisonFlagList // -C [f=f | f!=f] Comparison filter.
	Filter     FilterFlagList     // -F [n=v | n!=v | n<v | n>v | n<=v | n>=v | n&v | n&=v]
	Syscall    StringList         // -S Syscall name or number or "all". Value can be comma-separated.

	// Filepath watch (can be done more expressively using syscalls)
	Path        string             // -w Path for filesystem watch (no wildcards).
	Permissions FileAccessTypeFlag // -p [r|w|x|a] Permission filter.

	Key StringList // -k (max 31 bytes) Key(s) to associate with the rule.

	flagSet *flag.FlagSet
}

func newRuleFlagSet() *RuleFlagSet {
	rule := &RuleFlagSet{
		flagSet: flag.NewFlagSet("rule", flag.ContinueOnError),
	}
	rule.flagSet.SetOutput(ioutil.Discard)

	rule.flagSet.BoolVar(&rule.DeleteAll, "D", false, "delete all")
	rule.flagSet.Var(&rule.Append, "a", "append rule")
	rule.flagSet.Var(&rule.Prepend, "A", "prepend rule")
	rule.flagSet.Var(&rule.Comparison, "C", "comparison filter")
	rule.flagSet.Var(&rule.Filter, "F", "filter")
	rule.flagSet.Var(&rule.Syscall, "S", "syscall name, number, or 'all'")
	rule.flagSet.Var(&rule.Permissions, "p", "access type - r=read, w=write, x=execute, a=attribute change")
	rule.flagSet.StringVar(&rule.Path, "w", "", "path to watch, no wildcards")
	rule.flagSet.Var(&rule.Key, "k", "key")

	return rule
}

func (r *RuleFlagSet) Usage() string {
	buf := new(bytes.Buffer)
	r.flagSet.SetOutput(buf)
	r.flagSet.Usage()
	r.flagSet.SetOutput(ioutil.Discard)
	return buf.String()
}

func ParseRule(args string) (*RuleFlagSet, error) {
	rule := newRuleFlagSet()
	if err := rule.flagSet.Parse(strings.Fields(args)); err != nil {
		return nil, err
	}
	if err := rule.validate(); err != nil {
		return nil, err
	}

	return rule, nil
}

func (r *RuleFlagSet) validate() error {
	var (
		deleteAll uint8
		fileWatch uint8
		syscall   uint8
	)

	r.flagSet.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "D":
			deleteAll = 1
		case "w", "p":
			fileWatch = 1
		case "a", "A", "C", "F", "S":
			syscall = 1
		}
	})

	// Test for mutual exclusivity.
	switch deleteAll + fileWatch + syscall {
	case 0:
		return errors.New("missing an operation flag (add or delete rule)")
	case 1:
		switch {
		case deleteAll > 0:
			r.Type = DeleteAllRuleType
		case fileWatch > 0:
			r.Type = FileWatchRuleType
		case syscall > 0:
			r.Type = AppendSyscallRuleType
		}
	default:
		ops := make([]string, 0, 3)
		if deleteAll > 0 {
			ops = append(ops, "delete all [-D]")
		}
		if fileWatch > 0 {
			ops = append(ops, "file watch [-w|-p]")
		}
		if syscall > 0 {
			ops = append(ops, "audit rule [-a|-A|-S|-C|-F]")
		}
		return fmt.Errorf("mutually exclusive flags uses together (%v)",
			strings.Join(ops, " and "))
	}

	if syscall > 0 {
		var zero AddFlag
		if r.Prepend == zero && r.Append == zero {
			return errors.New("audit rules must specify either [-A] or [-a]")
		}
		if r.Prepend != zero && r.Append != zero {
			return fmt.Errorf("audit rules cannot specify both [-A] and [-a]")
		}
		if r.Prepend != zero {
			r.Type = PrependSyscallRuleType
		}
	}

	return nil
}
