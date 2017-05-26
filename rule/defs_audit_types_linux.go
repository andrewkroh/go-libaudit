//+build ignore

package rule

/*
#include <linux/audit.h>
#include <linux/stat.h>
*/
import "C"

type Filter uint32

// https://github.com/linux-audit/audit-kernel/blob/v3.15/include/uapi/linux/audit.h#L147-L157
const (
	FilterUser    Filter = C.AUDIT_FILTER_USER  /* Apply rule to user-generated messages */
	FilterTask    Filter = C.AUDIT_FILTER_TASK  /* Apply rule at task creation (not syscall) */
	FilterEntry   Filter = C.AUDIT_FILTER_ENTRY /* Apply rule at syscall entry */
	FilterWatch   Filter = C.AUDIT_FILTER_WATCH /* Apply rule to file system watches */
	FilterExit    Filter = C.AUDIT_FILTER_EXIT  /* Apply rule at syscall exit */
	FilterType    Filter = C.AUDIT_FILTER_TYPE  /* Apply rule at audit_log_start */
	FilterExclude        = FilterType

	FilterPrepend Filter = C.AUDIT_FILTER_PREPEND /* Prepend to front of list */
)

type Action uint32

// https://github.com/linux-audit/audit-kernel/blob/v3.15/include/uapi/linux/audit.h#L159-L162
const (
	ActionNever    Action = C.AUDIT_NEVER    /* Do not build context if rule matches */
	ActionPossible Action = C.AUDIT_POSSIBLE /* Build context if rule matches  */
	ActionAlways   Action = C.AUDIT_ALWAYS   /* Generate audit record if rule matches */
)

type Field uint32

/* Rule fields */
// Values >= 100 are ONLY useful when checking at syscall exit time (AUDIT_AT_EXIT).
const (
	AUIDField     Field = C.AUDIT_LOGINUID
	ArchField     Field = C.AUDIT_ARCH
	Arg0Field     Field = C.AUDIT_ARG0
	Arg1Field     Field = C.AUDIT_ARG1
	Arg2Field     Field = C.AUDIT_ARG2
	Arg3Field     Field = C.AUDIT_ARG3
	DevMajorField Field = C.AUDIT_DEVMAJOR
	DevMinorField Field = C.AUDIT_DEVMINOR
	DirField      Field = C.AUDIT_DIR
	EGIDField     Field = C.AUDIT_EGID
	EUIDField     Field = C.AUDIT_EUID
	//ExeField			    Field = C.AUDIT_EXE   // Added in v4.3.
	ExitField            Field = C.AUDIT_EXIT
	FSGIDField           Field = C.AUDIT_FSGID
	FSUIDField           Field = C.AUDIT_FSUID
	FiletypeField        Field = C.AUDIT_FILETYPE
	GIDField             Field = C.AUDIT_GID
	InodeField           Field = C.AUDIT_INODE
	KeyField             Field = C.AUDIT_FILTERKEY
	MsgTypeField         Field = C.AUDIT_MSGTYPE
	ObjectGIDField       Field = C.AUDIT_OBJ_GID
	ObjectLevelHighField Field = C.AUDIT_OBJ_LEV_HIGH
	ObjectLevelLowField  Field = C.AUDIT_OBJ_LEV_LOW
	ObjectRoleField      Field = C.AUDIT_OBJ_ROLE
	ObjectTypeField      Field = C.AUDIT_OBJ_TYPE
	ObjectUIDField       Field = C.AUDIT_OBJ_UID
	ObjectUserField      Field = C.AUDIT_OBJ_USER
	PathField            Field = C.AUDIT_WATCH
	PIDField             Field = C.AUDIT_PID
	PPIDField            Field = C.AUDIT_PPID
	PermField            Field = C.AUDIT_PERM
	PersField            Field = C.AUDIT_PERS
	//SessionIDField          Field = C.AUDIT_SESSIONID // Added in v4.10.
	SGIDField               Field = C.AUDIT_SGID
	SUIDField               Field = C.AUDIT_SUID
	SubjectClearanceField   Field = C.AUDIT_SUBJ_CLR
	SubjectRoleField        Field = C.AUDIT_SUBJ_ROLE
	SubjectSensitivityField Field = C.AUDIT_SUBJ_SEN
	SubjectTypeField        Field = C.AUDIT_SUBJ_TYPE
	SubjectUserField        Field = C.AUDIT_SUBJ_USER
	SuccessField            Field = C.AUDIT_SUCCESS
	UIDField                Field = C.AUDIT_UID

	FieldCompare Field = C.AUDIT_FIELD_COMPARE
)

type Operator uint32

// https://github.com/linux-audit/audit-kernel/blob/v3.15/include/uapi/linux/audit.h#L294-L301
const (
	BitMaskOperator            Operator = C.AUDIT_BIT_MASK
	LessThanOperator           Operator = C.AUDIT_LESS_THAN
	GreaterThanOperator        Operator = C.AUDIT_GREATER_THAN
	NotEqualOperator           Operator = C.AUDIT_NOT_EQUAL
	EqualOperator              Operator = C.AUDIT_EQUAL
	BitTestOperator            Operator = C.AUDIT_BIT_TEST
	LessThanOrEqualOperator    Operator = C.AUDIT_LESS_THAN_OR_EQUAL
	GreaterThanOrEqualOperator Operator = C.AUDIT_GREATER_THAN_OR_EQUAL
)

type Comparison uint32

const (
	AUDIT_COMPARE_UID_TO_OBJ_UID   Comparison = C.AUDIT_COMPARE_UID_TO_OBJ_UID
	AUDIT_COMPARE_GID_TO_OBJ_GID   Comparison = C.AUDIT_COMPARE_GID_TO_OBJ_GID
	AUDIT_COMPARE_EUID_TO_OBJ_UID  Comparison = C.AUDIT_COMPARE_EUID_TO_OBJ_UID
	AUDIT_COMPARE_EGID_TO_OBJ_GID  Comparison = C.AUDIT_COMPARE_EGID_TO_OBJ_GID
	AUDIT_COMPARE_AUID_TO_OBJ_UID  Comparison = C.AUDIT_COMPARE_AUID_TO_OBJ_UID
	AUDIT_COMPARE_SUID_TO_OBJ_UID  Comparison = C.AUDIT_COMPARE_SUID_TO_OBJ_UID
	AUDIT_COMPARE_SGID_TO_OBJ_GID  Comparison = C.AUDIT_COMPARE_SGID_TO_OBJ_GID
	AUDIT_COMPARE_FSUID_TO_OBJ_UID Comparison = C.AUDIT_COMPARE_FSUID_TO_OBJ_UID
	AUDIT_COMPARE_FSGID_TO_OBJ_GID Comparison = C.AUDIT_COMPARE_FSGID_TO_OBJ_GID

	AUDIT_COMPARE_UID_TO_AUID  Comparison = C.AUDIT_COMPARE_UID_TO_AUID
	AUDIT_COMPARE_UID_TO_EUID  Comparison = C.AUDIT_COMPARE_UID_TO_EUID
	AUDIT_COMPARE_UID_TO_FSUID Comparison = C.AUDIT_COMPARE_UID_TO_FSUID
	AUDIT_COMPARE_UID_TO_SUID  Comparison = C.AUDIT_COMPARE_UID_TO_SUID

	AUDIT_COMPARE_AUID_TO_FSUID Comparison = C.AUDIT_COMPARE_AUID_TO_FSUID
	AUDIT_COMPARE_AUID_TO_SUID  Comparison = C.AUDIT_COMPARE_AUID_TO_SUID
	AUDIT_COMPARE_AUID_TO_EUID  Comparison = C.AUDIT_COMPARE_AUID_TO_EUID

	AUDIT_COMPARE_EUID_TO_SUID  Comparison = C.AUDIT_COMPARE_EUID_TO_SUID
	AUDIT_COMPARE_EUID_TO_FSUID Comparison = C.AUDIT_COMPARE_EUID_TO_FSUID

	AUDIT_COMPARE_SUID_TO_FSUID Comparison = C.AUDIT_COMPARE_SUID_TO_FSUID

	AUDIT_COMPARE_GID_TO_EGID  Comparison = C.AUDIT_COMPARE_GID_TO_EGID
	AUDIT_COMPARE_GID_TO_FSGID Comparison = C.AUDIT_COMPARE_GID_TO_FSGID
	AUDIT_COMPARE_GID_TO_SGID  Comparison = C.AUDIT_COMPARE_GID_TO_SGID

	AUDIT_COMPARE_EGID_TO_FSGID Comparison = C.AUDIT_COMPARE_EGID_TO_FSGID
	AUDIT_COMPARE_EGID_TO_SGID  Comparison = C.AUDIT_COMPARE_EGID_TO_SGID
	AUDIT_COMPARE_SGID_TO_FSGID Comparison = C.AUDIT_COMPARE_SGID_TO_FSGID
)

type Permission uint32

const (
	ExecPerm  Permission = C.AUDIT_PERM_EXEC
	WritePerm Permission = C.AUDIT_PERM_WRITE
	ReadPerm  Permission = C.AUDIT_PERM_READ
	AttrPerm  Permission = C.AUDIT_PERM_ATTR
)

type Filetype uint32

const (
	FileFiletype      Filetype = C.S_IFREG
	SocketFiletype    Filetype = C.S_IFSOCK
	LinkFiletype      Filetype = C.S_IFLNK
	BlockFiletype     Filetype = C.S_IFBLK
	DirFiletype       Filetype = C.S_IFDIR
	CharacterFiletype Filetype = C.S_IFCHR
	FIFOFiletype      Filetype = C.S_IFIFO
)
