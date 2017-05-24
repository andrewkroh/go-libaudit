package rule

import (
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	flags := "-a always,exit -F arch=b64 -S sendto,sendmsg -F key=send"

	data, err := Create(flags)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(flags)
	t.Logf("%+v", data)
}

func TestAddFlag(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addFlag(rule, "exit"))
		assert.EqualValues(t, FilterExit, rule.flags)
	})

	t.Run("task", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addFlag(rule, "task"))
		assert.EqualValues(t, FilterTask, rule.flags)
	})

	t.Run("user", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addFlag(rule, "user"))
		assert.EqualValues(t, FilterUser, rule.flags)
	})

	t.Run("exclude", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addFlag(rule, "exclude"))
		assert.EqualValues(t, FilterExclude, rule.flags)
	})

	t.Run("invalid", func(t *testing.T) {
		rule := &Data{}
		assert.Error(t, addFlag(rule, "invalid"))
	})
}

func TestAddAction(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addAction(rule, "always"))
		assert.EqualValues(t, ActionAlways, rule.action)
	})

	t.Run("never", func(t *testing.T) {
		rule := &Data{}
		assert.NoError(t, addAction(rule, "never"))
		assert.EqualValues(t, ActionNever, rule.action)
	})

	t.Run("invalid", func(t *testing.T) {
		rule := &Data{}
		assert.Error(t, addAction(rule, "invalid"))
	})
}

func TestAddSyscall(t *testing.T) {
	t.Run("all", func(t *testing.T) {
		rule := &Data{}
		if err := addSyscall(rule, "all"); err != nil {
			t.Fatal(err)
		}
		assert.True(t, rule.allSyscalls)
	})

	t.Run("unknown", func(t *testing.T) {
		rule := &Data{}
		err := addSyscall(rule, "unknown")
		assert.Error(t, err)
	})

	t.Run("open", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("requires amd64")
		}
		const openSyscallNum = 2
		rule := &Data{}
		if err := addSyscall(rule, "open"); err != nil {
			t.Fatal(err)
		}
		if assert.Len(t, rule.syscalls, 1) {
			assert.EqualValues(t, openSyscallNum, rule.syscalls[0])
		}
	})
}

func TestAddFilter(t *testing.T) {
	t.Run("invalid operator", func(t *testing.T) {
		err := addFilter(&Data{}, "auid", "%", "0")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid operator")
		}
	})

	t.Run("invalid lhs", func(t *testing.T) {
		err := addFilter(&Data{}, "foobar", "=", "0")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid field")
		}
	})

	t.Run("disallow_exclude", func(t *testing.T) {
		rule := &Data{flags: FilterExclude}
		err := addFilter(rule, "perm", "=", "wa")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "cannot be used")
		}
	})

	t.Run("uid", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "uid", ">", "1000"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, UIDField, rule.fields[0])
		assert.EqualValues(t, GreaterThanOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 1000, rule.values[0])
	})
	t.Run("auid_name", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "auid", "=", "root"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, AUIDField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 0, rule.values[0])
	})

	t.Run("gid", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "gid", "<=", "500"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, GIDField, rule.fields[0])
		assert.EqualValues(t, LessThanOrEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 500, rule.values[0])
	})
	t.Run("egid", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "egid", "=", "wheel"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, EGIDField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 0, rule.values[0])
	})

	t.Run("exit", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "exit", "!=", "2"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, ExitField, rule.fields[0])
		assert.EqualValues(t, NotEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 2, rule.values[0])
	})

	t.Run("exit_negative", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "exit", "!=", "-1"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, ExitField, rule.fields[0])
		assert.EqualValues(t, NotEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, -1, rule.values[0])
	})

	t.Run("exit_named", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "exit", "!=", "EPERM"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, ExitField, rule.fields[0])
		assert.EqualValues(t, NotEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, int(syscall.EPERM), rule.values[0])
	})

	t.Run("exit_named_negative", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "exit", "!=", "-EPERM"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, ExitField, rule.fields[0])
		assert.EqualValues(t, NotEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, -1*int(syscall.EPERM), rule.values[0])
	})
}
