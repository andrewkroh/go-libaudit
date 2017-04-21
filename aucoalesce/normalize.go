package aucoalesce

import (
	"gopkg.in/yaml.v2"
)

var defaultNorms *NormalizationConfig

var syscallNorms = map[string]*Normalization{}
var recordTypeNorms = map[string]*Normalization{}

func init() {
	var err error
	defaultNorms, err = LoadNormalizationConfig([]byte(builtInNormalizations))
	if err != nil {
		panic("failed to parse built in normalization mappings")
	}

	for i := range defaultNorms.Normalizations {
		n := defaultNorms.Normalizations[i]
		for _, syscall := range n.Syscalls {
			syscallNorms[syscall] = &n
		}
		for _, recordType := range n.RecordTypes {
			recordTypeNorms[recordType] = &n
		}
	}
}

type NormalizationConfig struct {
	Normalizations []Normalization
}

type Normalization struct {
	Action      string        `yaml:"action"`
	Object      ObjectMapping `yaml:"object"`
	How         HowMapping    `yaml:"how"`
	RecordTypes []string      `yaml:"record_types"`
	Syscalls    []string      `yaml:"syscalls"`
}

type ObjectMapping struct {
	PrimaryFieldName string `yaml:"primary"`
	What             string `yaml:"what"`
	PathIndex        int    `yaml:"path_index"`
}

type HowMapping struct {
	FieldName string `yaml:"field"`
}

func LoadNormalizationConfig(b []byte) (*NormalizationConfig, error) {
	c := &NormalizationConfig{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

const builtInNormalizations = `
---
normalizations:
-
  action: opened-file
  object:
    what: file
  how:
    field: exe
  syscalls:
  - creat
  - fallocate
  - truncate
  - ftruncate
  - open
  - openat
  - readlink
  - readlinkat
-
  action: changed-file-attributes-of
  object:
    what: file
  how:
    field: exe
  syscalls:
  - setxattr
  - fsetxattr
  - lsetxattr
  - removexattr
  - fremovexattr
  - lremovexattr
-
  action: changed-file-permissions-of
  object:
    what: file
  how:
    field: exe
  syscalls:
  - chmod
  - fchmod
  - fchmodat
-
  action: changed-file-ownership-of
  object:
    what: file
  syscalls:
  - chown
  - fchown
  - fchownat
  - lchown
-
  action: loaded-kernel-module
  object:
    what: file
    primary: name
  record_types:
  - KERN_MODULE
  syscalls:
  - finit_module
  - init_module
-
  action: unloaded-kernel-module
  object:
    what: file
  syscalls:
  - delete_module
-
  action: created-directory
  object:
    what: file
  syscalls:
  - mkdir
  - mkdirat
-
  action: mounted
  object:
    what: filesystem
    path_index: 1
  syscalls:
  - mount
-
  action: renamed
  object:
    what: file
  syscalls:
  - mkdir
  - mkdirat
-
  action: checked-metadata-of
  object:
    what: file
  syscalls:
  - access
  - faccessat
  - newfstatat
  - stat
  - fstat
  - lstat
  - stat64
-
  action: checked-filesystem-metadata-of
  object:
    what: filesystem
  syscalls:
  - statfs
  - fstatfs
-
  action: symlinked
  object:
    what: file
  syscalls:
  - symlink
  - symlinkat
-
  action: unmounted
  object:
    what: filesystem
  syscalls:
  - umount2
-
  action: deleted
  object:
    what: file
  syscalls:
  - rmdir
  - unlink
  - unlinkat
-
  action: changed-timestamp-of
  object:
    what: file
  syscalls:
  - utime
  - utimes
  - futimesat
  - futimens
  - utimensat
-
  action: executed
  object:
    what: file
  syscalls:
  - execve
  - execveat
-
  action: accepted-connection-from
  object:
    what: socket
  syscalls:
  - accept
  - accept4
-
  action: bound-socket
  object:
    what: socket
  syscalls:
  - bind
-
  action: connected-to
  object:
    what: socket
  syscalls:
  - connect
-
  action: received-from
  object:
    what: socket
  syscalls:
  - recvfrom
  - recvmsg
-
  action: sent-to
  object:
    what: socket
  syscalls:
  - sendto
  - sendmsg
-
  action: killed-pid
  object:
    what: process
  syscalls:
  - kill
  - tkill
  - tgkill
-
  action: changed-identity-of
  object:
    what: program
  how:
    field: syscall
  syscalls:
  - setuid
  - seteuid
  - setfsuid
  - setreuid
  - setresuid
  - setgid
  - setegid
  - setfsgid
  - setregid
  - setresgid
-
  action: changed-system-time
  object:
    what: system
  how:
    field: exe
  syscalls:
  - settimeofday
  - clock_settime
  - stime
  - adjtimex
-
  action: make-device
  object:
    what: file
  syscalls:
  - mknod
  - mknodat
-
  action: changed-system-name
  object:
    what: system
  syscalls:
  - sethostname
  - setdomainname
-
  action: allocated-memory
  object:
    what: memory
  syscalls:
  - mmap
  - brk
-
  action: adjusted-scheduling-policy-of
  object:
    what: process
  how:
    field: syscall
  syscalls:
  - sched_setparam
  - sched_setscheduler
  - sched_setattr
# The following are simple records without an associated syscall message.
-
  action: caused-mac-policy-error
  object:
    what: system
  record_types:
  - SELINUX_ERR
-
  action: loaded-firewall-rule-to
  object:
    primary: table
    what: firewall
  record_types:
  - NETFILTER_CFG
-
  # Could be entered or exited based on prom field.
  action: changed-promiscuous-mode-on-device
  object:
    primary: dev
    what: socket
  record_types:
  - ANOM_PROMISCUOUS
`
