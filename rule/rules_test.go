package rule

import (
	"fmt"
	"io/ioutil"
	"math"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"path/filepath"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

type TestData struct {
	Rules []RuleTest `yaml:"rules"`
}

type RuleTest struct {
	Flags string `yaml:"flags"`
	Bytes string `yaml:"bytes"`
}

func TestBuildAuditRule(t *testing.T) {
	goldenFiles, err := filepath.Glob("testdata/*.rules.golden.yml")
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range goldenFiles {
		testRulesFromGoldenFile(t, file)
	}
}

func testRulesFromGoldenFile(t *testing.T, file string) {
	t.Run(filepath.Base(file), func(t *testing.T) {
		testdata, err := ioutil.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		var tests TestData
		if err := yaml.Unmarshal(testdata, &tests); err != nil {
			t.Fatal(err)
		}

		for i, test := range tests.Rules {
			t.Run(fmt.Sprintf("rule %d", i), func(t *testing.T) {
				if testing.Verbose() {
					t.Log("rule:", test.Flags)
				}

				actualBytes, err := BuildAuditRule(test.Flags)
				if err != nil {
					t.Fatal("rule:", test.Flags, "error:", err)
				}

				assert.Equal(t, []byte(test.Bytes), actualBytes, "rule: %v", test.Flags)
			})
		}
	})
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
		group, err := user.LookupGroupId("0")
		if err != nil {
			t.Fatal(err)
		}

		rule := &Data{}
		if err := addFilter(rule, "egid", "=", group.Name); err != nil {
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

	t.Run("msgtype", func(t *testing.T) {
		t.Run("exit", func(t *testing.T) {
			rule := &Data{flags: FilterExit}
			if err := addFilter(rule, "msgtype", "=", "EXECVE"); err == nil {
				t.Fatal("expected error")
			}
		})

		t.Run("user", func(t *testing.T) {
			rule := &Data{flags: FilterUser}
			if err := addFilter(rule, "msgtype", "=", "EXECVE"); err != nil {
				t.Fatal(err)
			}
			assert.EqualValues(t, MsgTypeField, rule.fields[0])
			assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
			assert.EqualValues(t, auparse.AUDIT_EXECVE, rule.values[0])
		})

		t.Run("exclude", func(t *testing.T) {
			rule := &Data{flags: FilterExclude}
			if err := addFilter(rule, "msgtype", "=", "1309"); err != nil {
				t.Fatal(err)
			}
			assert.EqualValues(t, MsgTypeField, rule.fields[0])
			assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
			assert.EqualValues(t, auparse.AUDIT_EXECVE, rule.values[0])
		})

		t.Run("unknown", func(t *testing.T) {
			rule := &Data{flags: FilterExclude}
			if err := addFilter(rule, "msgtype", "=", "UNKNOWN"); err == nil {
				t.Fatal("expected error")
			}
		})
	})

	t.Run("path", func(t *testing.T) {
		const etcPasswd = "/etc/passwd"
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "path", "=", etcPasswd); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, PathField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, etcPasswd, rule.strings[0])
	})

	t.Run("key_too_long", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "key", "=", strings.Repeat("x", AUDIT_MAX_KEY_LEN)); err != nil {
			t.Fatal(err)
		}
		if err := addFilter(rule, "key", "=", strings.Repeat("x", AUDIT_MAX_KEY_LEN+1)); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("arch_b32", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("arch test expects amd64")
		}
		rule := &Data{}
		if err := addFilter(rule, "arch", "=", "b32"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, ArchField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, auparse.AUDIT_ARCH_I386, rule.values[0])
	})

	t.Run("arch_b64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("arch test expects amd64")
		}
		rule := &Data{}
		if err := addFilter(rule, "arch", "=", "b64"); err != nil {
			t.Fatalf("%+v", err)
		}
		assert.EqualValues(t, ArchField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, auparse.AUDIT_ARCH_X86_64, rule.values[0])
	})

	t.Run("perm", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "perm", "=", "wa"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, PermField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, WritePerm|AttrPerm, rule.values[0])
	})

	t.Run("filetype", func(t *testing.T) {
		rule := &Data{flags: FilterExit}
		if err := addFilter(rule, "filetype", "=", "dir"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, FiletypeField, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, DirFiletype, rule.values[0])
	})

	t.Run("arg_max_uint32", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "a3", "=", strconv.FormatUint(math.MaxUint32, 10)); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, Arg3Field, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, math.MaxUint32, rule.values[0])
	})

	t.Run("arg_min_int32", func(t *testing.T) {
		rule := &Data{}
		if err := addFilter(rule, "a3", "=", strconv.FormatInt(math.MinInt32, 10)); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, Arg3Field, rule.fields[0])
		assert.EqualValues(t, EqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, math.MinInt32, rule.values[0])
	})
}
