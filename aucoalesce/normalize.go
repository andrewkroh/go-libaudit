// Copyright 2017 Elasticsearch Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aucoalesce

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	norms           *NormalizationConfig
	syscallNorms    = map[string]*Normalization{}
	recordTypeNorms = map[string]*Normalization{}
)

func init() {
	var err error
	norms, err = LoadNormalizationConfig([]byte(builtInNormalizations))
	if err != nil {
		panic(errors.Wrap(err, "failed to parse built in normalization mappings"))
	}

	for i := range norms.Normalizations {
		n := norms.Normalizations[i]
		for _, syscall := range n.Syscalls {
			syscallNorms[syscall] = &n
		}
		for _, recordType := range n.RecordTypes {
			recordTypeNorms[recordType] = &n
		}
	}
}

// Strings is a custom type to enable YAML values that can be either a string
// or a list of strings.
type Strings struct {
	Values []string
}

func (s *Strings) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var singleValue string
	if err := unmarshal(&singleValue); err == nil {
		s.Values = append(s.Values, singleValue)
		return nil
	}

	return unmarshal(&s.Values)
}

type NormalizationConfig struct {
	Default        Normalization `yaml:"default"`
	Normalizations []Normalization
}

type Normalization struct {
	Subject     SubjectMapping `yaml:"subject"`
	Action      string         `yaml:"action"`
	Object      ObjectMapping  `yaml:"object"`
	How         Strings        `yaml:"how"`
	RecordTypes []string       `yaml:"record_types"`
	Syscalls    []string       `yaml:"syscalls"`
}

type SubjectMapping struct {
	PrimaryFieldName   Strings `yaml:"primary"`
	SecondaryFieldName Strings `yaml:"secondary"`
}

type ObjectMapping struct {
	PrimaryFieldName   Strings `yaml:"primary"`
	SecondaryFieldName Strings `yaml:"secondary"`
	What               string  `yaml:"what"`
	PathIndex          int     `yaml:"path_index"`
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
default:
  subject:
    primary:   auid
    secondary: uid
  object:
    file:
      primary: name
      secondary: inode
      what: file
    socket:
      primary: addr
      secondary: port
      what: socket
  how: [exe, comm]

normalizations:
-
  action: opened-file
  object:
    what: file
  how: exe
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
  how: exe
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
  how: exe
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
  how: syscall
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
  how: exe
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
  how: syscall
  syscalls:
  - sched_setparam
  - sched_setscheduler
  - sched_setattr
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
    what: network-device
  record_types:
  - ANOM_PROMISCUOUS
-
  action: locked-account
  record_types:
  - ACCT_LOCK
-
  action: unlocked-account
  record_types:
  - ACCT_UNLOCK
-
  action: added-group-account-to
  object:
    primary: [id, acct]
    what: account
  record_types:
  - ADD_GROUP
-
  action: added-user-account
  object:
    primary: [id, acct]
    what: account
  record_types:
  - ADD_USER
-
  action: crashed-program
  object:
    primary: comm # Prefer exe, but it wasn't part of the one record I tested against.
    secondary: pid
    what: process
  how: sig
  record_types:
  - ANOM_ABEND
-
  action: attempted-execution-of-forbidden-program
  object:
    primary: cmd
    what: process
  how: terminal
  record_types:
  - ANOM_EXEC
-
  action: used-suspcious-link
  record_types:
  - ANOM_LINK
-
  action: failed-log-in-too-many-times-to
  object:
    primary: acct
    what: user-session
  record_types:
  - ANOM_LOGIN_FAILURES
-
  action: attempted-log-in-from-unusual-place-to
  object:
    primary: acct
    what: user-session
  record_types:
  - ANOM_LOGIN_LOCATION
-
  action: opened-too-many-sessions-to
  object:
    primary: acct
    what: user-session
  record_types:
  - ANOM_LOGIN_SESSIONS
-
  action: attempted-log-in-during-unusual-hour-to
  object:
    primary: acct
    what: user-session
  record_types:
  - ANOM_LOGIN_TIME
-
  action: tested-file-system-integrity-of
  object:
    primary: hostname
    what: filesystem
  record_types:
  - ANOM_RBAC_INTEGRITY_FAIL
-
  action: violated-selinux-policy
  subject:
    primary: scontext
  object:
    primary: tcontext
  record_types:
  - AVC
-
  action: changed-group
  record_types:
  - CHGRP_ID
-
  action: changed-user-id
  record_types:
  - CHUSER_ID
-
  action: changed-audit-configuration
  object:
    primary: [op, key, audit_enabled, audit_pid, audit_backlog_limit, audit_failure]
    what: audit-config
  record_types:
  - CONFIG_CHANGE
-
  action: acquired-credentials
  object:
    primary: acct
    what: user-session
  record_types:
  - CRED_ACQ
-
  action: disposed-credentials
  object:
    primary: acct
    what: user-session
  record_types:
  - CRED_DISP
-
  action: refreshed-credentials
  object:
    primary: acct
    what: user-session
  record_types:
  - CRED_REFR
-
  action: negotiated-crypto-key
  object:
    primary: fp
    what: user-session
  record_types:
  - CRYPTO_KEY_USER
-
  action: crypto-officer-logged-in
  record_types:
  - CRYPTO_LOGIN
-
  action: crypto-officer-logged-out
  record_types:
  - CRYPTO_LOGOUT
-
  action: started-crypto-session
  object:
    primary: addr
    secondary: rport
    what: user-session
  record_types:
  - CRYPTO_SESSION
-
  action: access-result
  record_types:
  - DAC_CHECK
-
  action: aborted-auditd-startup
  object:
    what: service
  record_types:
  - DAEMON_ABORT
-
  action: remote-audit-connected
  object:
    what: service
  record_types:
  - DAEMON_ACCEPT
-
  action: remote-audit-disconnected
  object:
    what: service
  record_types:
  - DAEMON_CLOSE
-
  action: changed-auditd-configuration
  object:
    what: service
  record_types:
  - DAEMON_CONFIG
-
  action: shutdown-audit
  object:
    what: service
  record_types:
  - DAEMON_END
-
  action: audit-error
  object:
    what: service
  record_types:
  - DAEMON_ERR
-
  action: reconfigured-auditd
  object:
    what: service
  record_types:
  - DAEMON_RECONFIG
-
  action: resumed-audit-logging
  object:
    what: service
  record_types:
  - DAEMON_RESUME
-
  action: rotated-audit-logs
  object:
    what: service
  record_types:
  - DAEMON_ROTATE
-
  action: started-audit
  object:
    what: service
  record_types:
  - DAEMON_START
-
  action: deleted-group-account-from
  object:
    primary: [id, acct]
    what: account
  record_types:
  - DEL_GROUP
-
  action: deleted-user-account
  object:
    primary: [id, acct]
    what: account
  record_types:
  - DEL_USER
-
  action: changed-audit-feature
  object:
    primary: feature
    what: system
  record_types:
  - FEATURE_CHANGE
-
  action: relabeled-filesystem
  record_types:
  - FS_RELABEL
-
  action: authenticated-to-group
  record_types:
  - GRP_AUTH
-
  action: changed-group-password
  object:
    primary: acct
    what: user-session
  record_types:
  - GRP_CHAUTHTOK
-
  action: modified-group-account
  object:
    primary: [id, acct]
    what: account
  record_types:
  - GRP_MGMT
-
  action: initialized-audit-subsystem
  record_types:
  - KERNEL
-
  action: loaded-kernel-module
  record_types:
  - KERN_MODULE
-
  action: modified-level-of
  object:
    primary: printer
    what: printer
  record_types:
  - LABEL_LEVEL_CHANGE
-
  action: overrode-label-of
  object:
    what: mac-config
  record_types:
  - LABEL_OVERRIDE
-
  object:
    what: mac-config
  record_types:
  - AUDIT_DEV_ALLOC
  - AUDIT_DEV_DEALLOC
  - AUDIT_FS_RELABEL
  - AUDIT_USER_MAC_POLICY_LOAD
  - AUDIT_USER_MAC_CONFIG_CHANGE
-
  action: changed-login-id-to
  subject:
    primary: [old_auid, old-auid]
    secondary: uid
  object:
    primary: auid
    what: user-session
  record_types:
  - LOGIN
-
  action: mac-permission
  record_types:
  - MAC_CHECK
-
  action: changed-selinux-boolean
  object:
    primary: bool
    what: mac-config
  record_types:
  - MAC_CONFIG_CHANGE
-
  action: loaded-selinux-policy
  object:
    what: mac-config
  record_types:
  - MAC_POLICY_LOAD
-
  action: changed-selinux-enforcement
  object:
    primary: enforcing
    what: mac-config
  record_types:
  - MAC_STATUS
-
  action: assigned-user-role-to
  object:
    primary: [id, acct]
    what: account
  record_types:
  - ROLE_ASSIGN
-
  action: modified-role
  record_types:
  - ROLE_MODIFY
-
  action: removed-use-role-from
  object:
    primary: [id, acct]
    what: account
  record_types:
  - ROLE_REMOVE
-
  action: violated-seccomp-policy
  object:
    primary: syscall
    what: process
  record_types:
  - SECCOMP
-
  action: started-service
  object:
    primary: unit
    what: service
  record_types:
  - SERVICE_START
-
  action: stopped-service
  object:
    primary: unit
    what: service
  record_types:
  - SERVICE_STOP
-
  action: booted-system
  object:
    what: system
  record_types:
  - SYSTEM_BOOT
-
  action: changed-to-runlevel
  object:
    primary: new-level
    what: system
  record_types:
  - SYSTEM_RUNLEVEL
-
  action: shutdown-system
  object:
    what: system
  record_types:
  - SYSTEM_SHUTDOWN
-
  action: sent-test
  record_types:
  - TEST
-
  action: unknown
  record_types:
  - TRUSTED_APP
-
  action: sent-message
  object:
    primary: addr
  record_types:
  - USER
-
  action: was-authorized
  object:
    primary: acct
    what: user-session
  record_types:
  - USER_ACCT
-
  action: authenticated
  object:
    primary: acct
    what: user-session
  record_types:
  - USER_AUTH
-
  action: access-permission
  record_types:
  - USER_AVC
-
  action: changed-password
  object:
    primary: acct
    what: user-session
  record_types:
  - USER_CHAUTHTOK
-
  action: ran-command
  object:
    primary: cmd
    what: process
  record_types:
  - USER_CMD
-
  action: ended-session
  object:
    primary: terminal
    what: user-session
  record_types:
  - USER_END
-
  action: error
  object:
    primary: terminal
    what: user-session
  record_types:
  - USER_ERR
-
  action: logged-in
  subject:
    primary: [id, acct]
  object:
    primary: terminal
    what: user-session
  how: [terminal, exe]
  record_types:
  - USER_LOGIN
-
  action: logged-out
  object:
    primary: terminal
    what: user-session
  record_types:
  - USER_LOGOUT
-
  action: changed-mac-configuration
  record_types:
  - USER_MAC_CONFIG_CHANGE
-
  action: loaded-mac-policy
  record_types:
  - USER_MAC_POLICY_LOAD
-
  action: modified-user-account
  object:
    primary: acct
    what: user-session
  record_types:
  - USER_MGMT
-
  action: changed-role-to
  object:
    primary: selected-context
    what: user-session
  record_types:
  - USER_ROLE_CHANGE
-
  action: access-error
  record_types:
  - USER_SELINUX_ERR
-
  action: started-session
  object:
    primary: terminal
    what: user-session
  record_types:
  - USER_START
-
  action: typed
  record_types:
  - USER_TTY
-
  action: changed-configuration
  object:
    primary: op
    what: system
  record_types:
  - USYS_CONFIG
-
  action: issued-vm-control
  object:
    primary: op
    secondary: vm
    what: virtual-machine
  record_types:
  - VIRT_CONTROL
-
  action: created-vm-image
  record_types:
  - VIRT_CREATE
-
  action: deleted-vm-image
  record_types:
  - VIRT_DESTROY
-
  action: checked-integrity-of
  record_types:
  - VIRT_INTEGRITY_CHECK
-
  action: assigned-vm-id
  object:
    primary: vm
    what: virtual-machine
  record_types:
  - VIRT_MACHINE_ID
-
  action: migrated-vm-from
  record_types:
  - VIRT_MIGRATE_IN
-
  action: migrated-vm-to
  record_types:
  - VIRT_MIGRATE_OUT
-
  action: assigned-vm-resource
  object:
    primary: resrc
    secondary: vm
    what: virtual-machine
  record_types:
  - VIRT_RESOURCE
`
