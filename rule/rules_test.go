package rule

import (
	"runtime"
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
		rule := &Data{}
		if err := addSyscall(rule, "open"); err != nil {
			t.Fatal(err)
		}
		if assert.Len(t, rule.syscalls, 1) {
			assert.EqualValues(t, 2, rule.syscalls[0])
		}
	})
}
