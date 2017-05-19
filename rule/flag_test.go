package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		rule    string
		flagSet *RuleFlagSet
	}{
		{
			"-w /etc/shadow -p wa -k identity",
			&RuleFlagSet{
				Type:        FileWatchRuleType,
				Path:        "/etc/shadow",
				Permissions: FileAccessTypeFlag{[]AccessType{WriteAccessType, AttributeChangeAccessType}},
				Key:         []string{"identity"},
			},
		},
		{
			"-w /etc/shadow -p cwa", nil,
		},
		{
			"-w /etc/shadow -p wa -k identity -k users",
			&RuleFlagSet{
				Type:        FileWatchRuleType,
				Path:        "/etc/shadow",
				Permissions: FileAccessTypeFlag{[]AccessType{WriteAccessType, AttributeChangeAccessType}},
				Key:         []string{"identity", "users"},
			},
		},
		{
			"-a always,exit -F path=/etc/shadow -F perm=wa",
			&RuleFlagSet{
				Type: AppendSyscallRuleType,
				Append: AddFlag{
					Action: "always",
					List:   "exit",
				},
				Filter: []FilterFlag{
					{
						LHS:        "path",
						Comparator: "=",
						RHS:        "/etc/shadow",
					},
					{
						LHS:        "perm",
						Comparator: "=",
						RHS:        "wa",
					},
				},
			},
		},
		{
			"-D",
			&RuleFlagSet{Type: DeleteAllRuleType, DeleteAll: true},
		},
		{
			"-E", nil,
		},
		{
			"-D -a exit,always", nil,
		},
		{
			"-k key", nil,
		},
		{
			"-D -k key",
			&RuleFlagSet{
				Type:      DeleteAllRuleType,
				DeleteAll: true,
				Key:       []string{"key"},
			},
		},
		{
			"-D -D",
			&RuleFlagSet{Type: DeleteAllRuleType, DeleteAll: true},
		},
		{
			"-a exit,always -A task,never", nil,
		},
		{
			"-A always,exit -C auid!=uid",
			&RuleFlagSet{
				Type: PrependSyscallRuleType,
				Prepend: AddFlag{
					Action: "always",
					List:   "exit",
				},
				Comparison: []ComparisonFlag{
					{
						LHS:        "auid",
						Comparator: "!=",
						RHS:        "uid",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		rule, err := ParseRule(tc.rule)
		if tc.flagSet == nil {
			if err == nil {
				t.Error("expected error in rule:", tc.rule)
			} else {
				t.Logf("parse error: %v in rule: %v", err, tc.rule)
			}
			continue
		}
		rule.flagSet = nil
		assert.EqualValues(t, tc.flagSet, rule, "error in %v", tc.rule)
		t.Logf("%+v", rule)
	}
}
