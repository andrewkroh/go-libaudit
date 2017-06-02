// Created by cgo -godefs - DO NOT EDIT
// cgo -godefs defs_audit_types_linux.go

package rule

type Filter uint32

const (
	FilterUser    Filter = 0x0
	FilterTask    Filter = 0x1
	FilterEntry   Filter = 0x2
	FilterWatch   Filter = 0x3
	FilterExit    Filter = 0x4
	FilterType    Filter = 0x5
	FilterExclude        = FilterType

	FilterPrepend Filter = 0x10
)

type Action uint32

const (
	ActionNever    Action = 0x0
	ActionPossible Action = 0x1
	ActionAlways   Action = 0x2
)

type Field uint32

const (
	AUIDField            Field = 0x9
	ArchField            Field = 0xb
	Arg0Field            Field = 0xc8
	Arg1Field            Field = 0xc9
	Arg2Field            Field = 0xca
	Arg3Field            Field = 0xcb
	DevMajorField        Field = 0x64
	DevMinorField        Field = 0x65
	DirField             Field = 0x6b
	EGIDField            Field = 0x6
	EUIDField            Field = 0x2
	ExeField             Field = 0x70
	ExitField            Field = 0x67
	FSGIDField           Field = 0x8
	FSUIDField           Field = 0x4
	FiletypeField        Field = 0x6c
	GIDField             Field = 0x5
	InodeField           Field = 0x66
	KeyField             Field = 0xd2
	MsgTypeField         Field = 0xc
	ObjectGIDField       Field = 0x6e
	ObjectLevelHighField Field = 0x17
	ObjectLevelLowField  Field = 0x16
	ObjectRoleField      Field = 0x14
	ObjectTypeField      Field = 0x15
	ObjectUIDField       Field = 0x6d
	ObjectUserField      Field = 0x13
	PathField            Field = 0x69
	PIDField             Field = 0x0
	PPIDField            Field = 0x12
	PermField            Field = 0x6a
	PersField            Field = 0xa

	SGIDField               Field = 0x7
	SUIDField               Field = 0x3
	SubjectClearanceField   Field = 0x11
	SubjectRoleField        Field = 0xe
	SubjectSensitivityField Field = 0x10
	SubjectTypeField        Field = 0xf
	SubjectUserField        Field = 0xd
	SuccessField            Field = 0x68
	UIDField                Field = 0x1

	FieldCompare Field = 0x6f
)

type Operator uint32

const (
	BitMaskOperator            Operator = 0x8000000
	LessThanOperator           Operator = 0x10000000
	GreaterThanOperator        Operator = 0x20000000
	NotEqualOperator           Operator = 0x30000000
	EqualOperator              Operator = 0x40000000
	BitTestOperator            Operator = 0x48000000
	LessThanOrEqualOperator    Operator = 0x50000000
	GreaterThanOrEqualOperator Operator = 0x60000000
)

type Comparison uint32

const (
	AUDIT_COMPARE_UID_TO_OBJ_UID   Comparison = 0x1
	AUDIT_COMPARE_GID_TO_OBJ_GID   Comparison = 0x2
	AUDIT_COMPARE_EUID_TO_OBJ_UID  Comparison = 0x3
	AUDIT_COMPARE_EGID_TO_OBJ_GID  Comparison = 0x4
	AUDIT_COMPARE_AUID_TO_OBJ_UID  Comparison = 0x5
	AUDIT_COMPARE_SUID_TO_OBJ_UID  Comparison = 0x6
	AUDIT_COMPARE_SGID_TO_OBJ_GID  Comparison = 0x7
	AUDIT_COMPARE_FSUID_TO_OBJ_UID Comparison = 0x8
	AUDIT_COMPARE_FSGID_TO_OBJ_GID Comparison = 0x9

	AUDIT_COMPARE_UID_TO_AUID  Comparison = 0xa
	AUDIT_COMPARE_UID_TO_EUID  Comparison = 0xb
	AUDIT_COMPARE_UID_TO_FSUID Comparison = 0xc
	AUDIT_COMPARE_UID_TO_SUID  Comparison = 0xd

	AUDIT_COMPARE_AUID_TO_FSUID Comparison = 0xe
	AUDIT_COMPARE_AUID_TO_SUID  Comparison = 0xf
	AUDIT_COMPARE_AUID_TO_EUID  Comparison = 0x10

	AUDIT_COMPARE_EUID_TO_SUID  Comparison = 0x11
	AUDIT_COMPARE_EUID_TO_FSUID Comparison = 0x12

	AUDIT_COMPARE_SUID_TO_FSUID Comparison = 0x13

	AUDIT_COMPARE_GID_TO_EGID  Comparison = 0x14
	AUDIT_COMPARE_GID_TO_FSGID Comparison = 0x15
	AUDIT_COMPARE_GID_TO_SGID  Comparison = 0x16

	AUDIT_COMPARE_EGID_TO_FSGID Comparison = 0x17
	AUDIT_COMPARE_EGID_TO_SGID  Comparison = 0x18
	AUDIT_COMPARE_SGID_TO_FSGID Comparison = 0x19
)

type Permission uint32

const (
	ExecPerm  Permission = 0x1
	WritePerm Permission = 0x2
	ReadPerm  Permission = 0x4
	AttrPerm  Permission = 0x8
)

type Filetype uint32

const (
	FileFiletype      Filetype = 0x8000
	SocketFiletype    Filetype = 0xc000
	LinkFiletype      Filetype = 0xa000
	BlockFiletype     Filetype = 0x6000
	DirFiletype       Filetype = 0x4000
	CharacterFiletype Filetype = 0x2000
	FIFOFiletype      Filetype = 0x1000
)
