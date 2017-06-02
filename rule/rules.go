package rule

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/pkg/errors"
)

//go:generate sh -c "go tool cgo -godefs defs_audit_types_linux.go > zaudit_types.go && gofmt -w zaudit_types.go"

const (
	AUDIT_BITMASK_SIZE = 64
	AUDIT_MAX_FIELDS   = 64
	AUDIT_MAX_KEY_LEN  = 256
	PathMax            = 4096 // PATH_MAX
	KeySeparator       = 0x01 // AUDIT_KEY_SEPARATOR
)

// auditRuleData supports filter rules with both integer and string
// fields.  It corresponds with AUDIT_ADD_RULE, AUDIT_DEL_RULE and
// AUDIT_LIST_RULES requests.
// https://github.com/linux-audit/audit-kernel/blob/v3.15/include/uapi/linux/audit.h#L423-L437
type AuditRuleData struct {
	Flags      Filter
	Action     Action
	FieldCount uint32
	Mask       [AUDIT_BITMASK_SIZE]uint32 // Syscalls affected.
	Fields     [AUDIT_MAX_FIELDS]Field
	Values     [AUDIT_MAX_FIELDS]uint32
	FieldFlags [AUDIT_MAX_FIELDS]Operator
	BufLen     uint32 // Total length of buffer used for string fields.
	Buf        []byte // String fields.
}

func (r AuditRuleData) toWireFormat() []byte {
	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, r.Flags)
	binary.Write(out, binary.LittleEndian, r.Action)
	binary.Write(out, binary.LittleEndian, r.FieldCount)
	binary.Write(out, binary.LittleEndian, r.Mask)
	binary.Write(out, binary.LittleEndian, r.Fields)
	binary.Write(out, binary.LittleEndian, r.Values)
	binary.Write(out, binary.LittleEndian, r.FieldFlags)
	binary.Write(out, binary.LittleEndian, r.BufLen)
	out.Write(r.Buf)

	// Adding padding.
	if out.Len()%4 > 0 {
		out.Write(make([]byte, 4-(out.Len()%4)))
	}

	return out.Bytes()
}

func FromWireFormat(data []byte) (*AuditRuleData, error) {
	var partialRule struct {
		Flags      Filter
		Action     Action
		FieldCount uint32
		Mask       [AUDIT_BITMASK_SIZE]uint32
		Fields     [AUDIT_MAX_FIELDS]Field
		Values     [AUDIT_MAX_FIELDS]uint32
		FieldFlags [AUDIT_MAX_FIELDS]Operator
		BufLen     uint32
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &partialRule); err != nil {
		return nil, errors.Wrap(err, "deserialization of rule data failed")
	}

	rule := &AuditRuleData{
		Flags:      partialRule.Flags,
		Action:     partialRule.Action,
		FieldCount: partialRule.FieldCount,
		Mask:       partialRule.Mask,
		Fields:     partialRule.Fields,
		Values:     partialRule.Values,
		FieldFlags: partialRule.FieldFlags,
		BufLen:     partialRule.BufLen,
	}

	if reader.Len() < int(rule.BufLen) {
		return nil, io.ErrUnexpectedEOF
	}

	rule.Buf = make([]byte, rule.BufLen)
	if _, err := reader.Read(rule.Buf); err != nil {
		return nil, err
	}

	return rule, nil
}

func PrintRule(r *AuditRuleData) {
	fmt.Println(base64.StdEncoding.EncodeToString(r.toWireFormat()))
	for _, f := range []Filter{FilterUser, FilterTask, FilterEntry, FilterWatch, FilterExit, FilterType, FilterPrepend} {
		if r.Flags&f > 0 {
			fmt.Println("filter =", f)
		}
	}
}

func Create(flags string) (*Data, error) {
	flagSet, err := ParseRule(flags)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse rule")
	}

	rule := &Data{allSyscalls: true}
	switch flagSet.Type {
	case AppendSyscallRuleType:
		if err = addFlag(rule, flagSet.Append.List); err != nil {
			return nil, err
		}
		if err = addAction(rule, flagSet.Append.Action); err != nil {
			return nil, err
		}
	case PrependSyscallRuleType:
		if err = addFlag(rule, flagSet.Prepend.List); err != nil {
			return nil, err
		}
		if err = addAction(rule, flagSet.Prepend.Action); err != nil {
			return nil, err
		}
	case FileWatchRuleType:
		return nil, errors.New("file watch rules are not implemented, use syscall rules")
	case DeleteAllRuleType:
		return nil, errors.New("delete all is not a rule type")
	}

	for _, filter := range flagSet.Filter {
		if err = addFilter(rule, filter.LHS, filter.Comparator, filter.RHS); err != nil {
			return nil, errors.Wrapf(err, "failed to add filter '%v'", filter)
		}
	}

	for _, compare := range flagSet.Comparison {
		if err = addInterFieldComparator(rule, compare.LHS, compare.Comparator, compare.RHS); err != nil {
			return nil, errors.Wrapf(err, "failed to add interfield comparison '%v'", flagSet.Comparison)
		}
	}

	for _, syscall := range flagSet.Syscall {
		if err = addSyscall(rule, syscall); err != nil {
			return nil, errors.Wrapf(err, "failed to add syscall '%v'", syscall)
		}
	}

	if len(flagSet.Key) > 0 {
		keys := strings.Join(flagSet.Key, string(KeySeparator))
		if err = addFilter(rule, "key", "=", keys); err != nil {
			return nil, errors.Wrapf(err, "failed to add keys [%v]", strings.Join(flagSet.Key, ","))
		}
	}

	return rule, nil
}

type Data struct {
	flags  Filter
	action Action

	allSyscalls bool
	syscalls    []uint32

	fields     []Field
	values     []uint32
	fieldFlags []Operator

	strings []string

	arch string
}

func (d Data) BuildRule() (*AuditRuleData, error) {
	rule := &AuditRuleData{
		Flags:      d.flags,
		Action:     d.action,
		FieldCount: uint32(len(d.fields)),
	}

	if d.allSyscalls {
		for i := 0; i < len(rule.Mask)-1; i++ {
			rule.Mask[i] = 0xFFFFFFFF
		}
	} else {
		for _, syscallNum := range d.syscalls {
			word := syscallNum / 32
			var bit uint32 = 1 << (syscallNum - (word * 32))
			if int(word) > len(rule.Mask) {
				return nil, errors.Errorf("invalid syscall number %v", syscallNum)
			}
			rule.Mask[word] |= bit
		}
	}

	if len(d.fields) > len(rule.Fields) {
		return nil, errors.Errorf("too many filters and keys, only %v total are supported", len(rule.Fields))
	}
	for i := range d.fields {
		rule.Fields[i] = d.fields[i]
		rule.FieldFlags[i] = d.fieldFlags[i]
		rule.Values[i] = d.values[i]
	}

	for _, s := range d.strings {
		rule.Buf = append(rule.Buf, []byte(s)...)
	}
	rule.BufLen = uint32(len(rule.Buf))

	return rule, nil
}

func BuildAuditRule(flags string) ([]byte, error) {
	data, err := Create(flags)
	if err != nil {
		return nil, err
	}

	auditRule, err := data.BuildRule()
	if err != nil {
		return nil, err
	}

	return auditRule.toWireFormat(), nil
}

func addFlag(rule *Data, list string) error {
	switch list {
	case "exit":
		rule.flags = FilterExit
	case "task":
		rule.flags = FilterTask
	case "user":
		rule.flags = FilterUser
	case "exclude":
		rule.flags = FilterExclude
	default:
		return errors.Errorf("invalid list '%v'", list)
	}

	return nil
}

func addAction(rule *Data, action string) error {
	switch action {
	case "always":
		rule.action = ActionAlways
	case "never":
		rule.action = ActionNever
	default:
		return errors.Errorf("invalid action '%v'", action)
	}

	return nil
}

// Convert name to number.
// Look for conditions when arch needs to be specified.
// Add syscall bit to mask.
func addSyscall(rule *Data, syscall string) error {
	if syscall == "all" {
		rule.allSyscalls = true
		return nil
	} else {
		rule.allSyscalls = false
	}

	syscallNum, err := strconv.Atoi(syscall)
	if nerr, ok := err.(*strconv.NumError); ok {
		if nerr.Err != strconv.ErrSyntax {
			return errors.Wrapf(err, "failed to parse syscall number '%v'", syscall)
		}

		arch := rule.arch
		if arch == "" {
			arch, err = getRuntimeArch()
			if err != nil {
				return errors.Wrap(err, "failed to add syscall")
			}
		}

		// Convert name to number.
		table, found := ReverseSyscall[arch]
		if !found {
			return errors.Errorf("syscall table not found for arch %v", arch)
		}

		syscallNum, found = table[syscall]
		if !found {
			return errors.Errorf("unknown syscall '%v' for arch %v", syscall, arch)
		}
	}

	rule.syscalls = append(rule.syscalls, uint32(syscallNum))
	return nil
}

func addFilter(rule *Data, lhs, comparator, rhs string) error {
	op, found := operatorsTable[comparator]
	if !found {
		return errors.Errorf("invalid operator '%v'", comparator)
	}

	field, found := fieldsTable[lhs]
	if !found {
		return errors.Errorf("invalid field '%v' on left", lhs)
	}

	// Only newer kernel versions support exclude for credential types. Older
	// kernels only support exclude on the msgtype field.
	if rule.flags == FilterExclude {
		switch field {
		case PIDField, UIDField, GIDField, AUIDField, MsgTypeField,
			SubjectUserField, SubjectRoleField, SubjectTypeField,
			SubjectSensitivityField, SubjectClearanceField:
		default:
			return errors.Errorf("field '%v' cannot be used the exclude flag", lhs)
		}
	}

	switch field {
	case UIDField, EUIDField, SUIDField, FSUIDField, AUIDField, ObjectUIDField:
		// Convert RHS to number.
		// Or attempt to lookup the name to get the number.
		uid, err := getUID(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uid)
	case GIDField, EGIDField, SGIDField, FSGIDField, ObjectGIDField:
		gid, err := getGID(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, gid)
	case ExitField:
		// Flag must be FilterExit.
		if rule.flags != FilterExit {
			return errors.New("exit filter can only be applied to syscall exit")
		}
		exitCode, err := getExitCode(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uint32(exitCode))
	case MsgTypeField:
		// Flag must be exclude or user.
		if rule.flags != FilterUser && rule.flags != FilterExclude {
			return errors.New("msgtype filter can only be applied to the user or exclude lists")
		}
		msgType, err := getAuditMsgType(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, msgType)
	case ObjectUserField, ObjectRoleField, ObjectTypeField, ObjectLevelLowField,
		ObjectLevelHighField, PathField, DirField:
		// Flag must be FilterExit.
		if rule.flags != FilterExit {
			return errors.Errorf("%v filter can only be applied to the syscall exit", lhs)
		}
		fallthrough
	case SubjectUserField, SubjectRoleField, SubjectTypeField,
		SubjectSensitivityField, SubjectClearanceField, KeyField:
		// ExeField:
		// Add string to strings.
		if field == KeyField && len(rhs) > AUDIT_MAX_KEY_LEN {
			return errors.Errorf("%v cannot be longer than %v", lhs, AUDIT_MAX_KEY_LEN)
		} else if len(rhs) > PathMax {
			return errors.Errorf("%v cannot be longer than %v", lhs, PathMax)
		}
		rule.values = append(rule.values, uint32(len(rhs)))
		rule.strings = append(rule.strings, rhs)
	case ArchField:
		// Arch should come before syscall.
		// Arch only supports = and !=.
		if op != EqualOperator && op != NotEqualOperator {
			return errors.Errorf("arch only supports the = and != operators")
		}
		// Or convert name to arch or validate given arch.
		archName, arch, err := getArch(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, arch)
		rule.arch = archName
	case PermField:
		// Perm is only valid for exit.
		if rule.flags != FilterExit {
			return errors.Errorf("perm filter can only be applied to the syscall exit")
		}
		// Perm is only valid for =.
		if op != EqualOperator {
			return errors.Errorf("perm only support the = operator")
		}
		perm, err := getPerm(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, perm)
	case FiletypeField:
		// Filetype is only valid for exit.
		if rule.flags != FilterExit {
			return errors.Errorf("filetype filter can only be applied to the syscall exit")
		}
		filetype, err := getFiletype(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uint32(filetype))
	case Arg0Field, Arg1Field, Arg2Field, Arg3Field:
		// Convert RHS to a number.
		arg, err := ParseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, arg)
	//case SessionIDField:
	case InodeField:
		// Flag must be FilterExit.
		if rule.flags != FilterExit {
			return errors.Errorf("inode filter can only be applied to the syscall exit")
		}
		// Comparator must be = or !=.
		if op != EqualOperator && op != NotEqualOperator {
			return errors.Errorf("inode only supports the = and != operators")
		}
		// Convert RHS to number.
		inode, err := ParseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, inode)
	case DevMajorField, DevMinorField, SuccessField, PPIDField:
		// Flag must be FilterExit.
		if rule.flags != FilterExit {
			return errors.Errorf("%v filter can only be applied to the syscall exit", lhs)
		}
		fallthrough
	default:
		// Convert RHS to number.
		num, err := ParseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, num)
	}

	rule.fields = append(rule.fields, field)
	rule.fieldFlags = append(rule.fieldFlags, op)
	return nil
}

func getUID(uid string) (uint32, error) {
	if uid == "unset" || uid == "-1" {
		return 4294967295, nil
	}

	v, err := strconv.ParseUint(uid, 10, 32)
	if nerr, ok := err.(*strconv.NumError); ok {
		if nerr.Err != strconv.ErrSyntax {
			return 0, errors.Wrapf(err, "failed to parse uid '%v'", uid)
		}

		u, err := user.Lookup(uid)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to convert user '%v' to a numeric ID", uid)
		}

		v, err = strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to parse uid '%v' belonging to user '%v'", u.Uid, u.Username)
		}
	}

	return uint32(v), nil
}

func getGID(gid string) (uint32, error) {
	v, err := strconv.ParseUint(gid, 10, 32)
	if nerr, ok := err.(*strconv.NumError); ok {
		if nerr.Err != strconv.ErrSyntax {
			return 0, errors.Wrapf(err, "failed to parse gid '%v'", gid)
		}

		g, err := user.LookupGroup(gid)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to convert group '%v' to a numeric ID", gid)
		}

		v, err = strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to parse gid '%v' belonging to group '%v'", g.Gid, g.Name)
		}
	}

	return uint32(v), nil
}

func getExitCode(exit string) (int32, error) {
	v, err := strconv.ParseInt(exit, 0, 32)
	if nerr, ok := err.(*strconv.NumError); ok {
		if nerr.Err != strconv.ErrSyntax {
			return 0, errors.Wrapf(err, "failed to parse exit code '%v'", exit)
		}

		sign := 1
		code := exit
		if strings.HasPrefix(exit, "-") {
			sign = -1
			code = exit[1:]
		}

		num, found := auparse.AuditErrnoToNum[code]
		if !found {
			return 0, errors.Errorf("failed to convert error to exit code '%v'", exit)
		}
		v = int64(sign * num)
	}

	return int32(v), nil
}

func getArch(arch string) (string, uint32, error) {
	var realArch = arch
	switch strings.ToLower(arch) {
	case "b64":
		runtimeArch, err := getRuntimeArch()
		if err != nil {
			return "", 0, err
		}

		switch runtimeArch {
		case "aarch64", "x86_64", "ppc":
			realArch = runtimeArch
		default:
			return "", 0, errors.Errorf("cannot use b64 on %v", runtimeArch)
		}
	case "b32":
		runtimeArch, err := getRuntimeArch()
		if err != nil {
			return "", 0, err
		}

		switch runtimeArch {
		case "arm", "i386":
			realArch = runtimeArch
		case "aarch64":
			realArch = "arm"
		case "x86_64":
			realArch = "i386"
		default:
			return "", 0, errors.Errorf("cannot use b32 on %v", runtimeArch)
		}
	}

	archValue, found := ReverseArch[realArch]
	if !found {
		return "", 0, errors.Errorf("unknown arch '%v'", arch)
	}
	return realArch, archValue, nil
}

// getRuntimeArch returns the programs arch (not the machines arch).
func getRuntimeArch() (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "arm":
		arch = "arm"
	case "arm64":
		arch = "aarch64"
	case "386":
		arch = "i386"
	case "amd64":
		arch = "x86_64"
	case "ppc64", "ppc64le":
		arch = "ppc"
	case "mips", "mipsle", "mips64", "mips64le":
		fallthrough
	default:
		return "", errors.Errorf("unsupported arch: %v", runtime.GOARCH)
	}

	return arch, nil
}

func getAuditMsgType(msgType string) (uint32, error) {
	v, err := strconv.ParseUint(msgType, 0, 32)
	if nerr, ok := err.(*strconv.NumError); ok {
		if nerr.Err != strconv.ErrSyntax {
			return 0, errors.Wrapf(err, "failed to parse msgtype '%v'", msgType)
		}

		typ, err := auparse.GetAuditMessageType(msgType)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to convert msgtype '%v' to numeric value", msgType)
		}
		v = uint64(typ)
	}

	return uint32(v), nil
}

func getPerm(perm string) (uint32, error) {
	var permBits Permission
	for _, p := range perm {
		switch p {
		case 'r':
			permBits |= ReadPerm
		case 'w':
			permBits |= WritePerm
		case 'x':
			permBits |= ExecPerm
		case 'a':
			permBits |= AttrPerm
		default:
			return 0, errors.Errorf("invalid permission access type '%v'", p)
		}
	}

	return uint32(permBits), nil
}

func getFiletype(filetype string) (Filetype, error) {
	switch strings.ToLower(filetype) {
	case "file":
		return FileFiletype, nil
	case "dir":
		return DirFiletype, nil
	case "socket":
		return SocketFiletype, nil
	case "symlink":
		return LinkFiletype, nil
	case "char":
		return CharacterFiletype, nil
	case "block":
		return BlockFiletype, nil
	case "fifo":
		return FIFOFiletype, nil
	default:
		return 0, errors.Errorf("invalid filetype '%v'", filetype)
	}
}

func ParseNum(num string) (uint32, error) {
	if strings.HasPrefix(num, "-") {
		v, err := strconv.ParseInt(num, 0, 32)
		return uint32(v), err
	} else {
		v, err := strconv.ParseUint(num, 0, 32)
		return uint32(v), err
	}
}

func addInterFieldComparator(rule *Data, lhs, comparator, rhs string) error {
	op, found := operatorsTable[comparator]
	if !found {
		return errors.Errorf("invalid operator '%v'", comparator)
	}

	switch op {
	case EqualOperator, NotEqualOperator:
	default:
		return errors.Errorf("invalid operator '%v', only '=' or '!=' can be used", comparator)
	}

	leftField, found := fieldsTable[lhs]
	if !found {
		return errors.Errorf("invalid field '%v' on left", lhs)
	}

	rightField, found := fieldsTable[rhs]
	if !found {
		return errors.Errorf("invalid field '%v' on right", lhs)
	}

	table, found := comparisonsTable[leftField]
	if !found {
		return errors.Errorf("field '%v' cannot be used in an interfield comparison", lhs)
	}

	comparison, found := table[rightField]
	if !found {
		return errors.Errorf("field '%v' cannot be used in an interfield comparison", rhs)
	}

	rule.fields = append(rule.fields, FieldCompare)
	rule.fieldFlags = append(rule.fieldFlags, op)
	rule.values = append(rule.values, uint32(comparison))

	return nil
}

var operatorsTable = map[string]Operator{
	"&":  BitMaskOperator,
	"<":  LessThanOperator,
	">":  GreaterThanOperator,
	"!=": NotEqualOperator,
	"=":  EqualOperator,
	"&=": BitTestOperator,
	"<=": LessThanOrEqualOperator,
	">=": GreaterThanOrEqualOperator,
}

var fieldsTable = map[string]Field{
	"auid":         AUIDField,
	"arch":         ArchField,
	"a0":           Arg0Field,
	"a1":           Arg1Field,
	"a2":           Arg2Field,
	"a3":           Arg3Field,
	"devmajor":     DevMajorField,
	"devminor":     DevMinorField,
	"dir":          DirField,
	"egid":         EGIDField,
	"euid":         EUIDField,
	"exit":         ExitField,
	"fsgid":        FSGIDField,
	"fsuid":        FSUIDField,
	"filetype":     FiletypeField,
	"gid":          GIDField,
	"inode":        InodeField,
	"key":          KeyField,
	"msgtype":      MsgTypeField,
	"obj_gid":      ObjectGIDField,
	"obj_lev_high": ObjectLevelHighField,
	"obj_lev_low":  ObjectLevelLowField,
	"obj_role":     ObjectRoleField,
	"obj_type":     ObjectTypeField,
	"obj_uid":      ObjectUIDField,
	"obj_user":     ObjectUserField,
	"path":         PathField,
	"pid":          PIDField,
	"ppid":         PPIDField,
	"perm":         PermField,
	"pers":         PersField,
	"sgid":         SGIDField,
	"suid":         SUIDField,
	"subj_clr":     SubjectClearanceField,
	"subj_role":    SubjectRoleField,
	"subj_sen":     SubjectSensitivityField,
	"subj_type":    SubjectTypeField,
	"subj_user":    SubjectUserField,
	"success":      SuccessField,
	"uid":          UIDField,
}

var comparisonsTable = map[Field]map[Field]Comparison{
	EUIDField: {
		AUIDField:      AUDIT_COMPARE_AUID_TO_EUID,
		FSUIDField:     AUDIT_COMPARE_EUID_TO_FSUID,
		ObjectUIDField: AUDIT_COMPARE_EUID_TO_OBJ_UID,
		SUIDField:      AUDIT_COMPARE_EUID_TO_SUID,
		UIDField:       AUDIT_COMPARE_UID_TO_EUID,
	},
	FSUIDField: {
		AUIDField:      AUDIT_COMPARE_AUID_TO_FSUID,
		EUIDField:      AUDIT_COMPARE_EUID_TO_FSUID,
		ObjectUIDField: AUDIT_COMPARE_FSUID_TO_OBJ_UID,
		SUIDField:      AUDIT_COMPARE_SUID_TO_FSUID,
		UIDField:       AUDIT_COMPARE_UID_TO_FSUID,
	},
	AUIDField: {
		EUIDField:      AUDIT_COMPARE_AUID_TO_EUID,
		FSUIDField:     AUDIT_COMPARE_AUID_TO_FSUID,
		ObjectUIDField: AUDIT_COMPARE_AUID_TO_OBJ_UID,
		SUIDField:      AUDIT_COMPARE_AUID_TO_SUID,
		UIDField:       AUDIT_COMPARE_UID_TO_AUID,
	},
	SUIDField: {
		AUIDField:      AUDIT_COMPARE_AUID_TO_SUID,
		EUIDField:      AUDIT_COMPARE_EUID_TO_SUID,
		FSUIDField:     AUDIT_COMPARE_SUID_TO_FSUID,
		ObjectUIDField: AUDIT_COMPARE_SUID_TO_OBJ_UID,
		UIDField:       AUDIT_COMPARE_UID_TO_SUID,
	},
	ObjectUIDField: {
		AUIDField:  AUDIT_COMPARE_AUID_TO_OBJ_UID,
		EUIDField:  AUDIT_COMPARE_EUID_TO_OBJ_UID,
		FSUIDField: AUDIT_COMPARE_FSUID_TO_OBJ_UID,
		UIDField:   AUDIT_COMPARE_UID_TO_OBJ_UID,
		SUIDField:  AUDIT_COMPARE_SUID_TO_OBJ_UID,
	},
	UIDField: {
		AUIDField:      AUDIT_COMPARE_UID_TO_AUID,
		EUIDField:      AUDIT_COMPARE_UID_TO_EUID,
		FSUIDField:     AUDIT_COMPARE_UID_TO_FSUID,
		ObjectUIDField: AUDIT_COMPARE_UID_TO_OBJ_UID,
		SUIDField:      AUDIT_COMPARE_UID_TO_SUID,
	},
	EGIDField: {
		FSGIDField:     AUDIT_COMPARE_EGID_TO_FSGID,
		GIDField:       AUDIT_COMPARE_GID_TO_EGID,
		ObjectGIDField: AUDIT_COMPARE_EGID_TO_OBJ_GID,
		SGIDField:      AUDIT_COMPARE_EGID_TO_SGID,
	},
	FSGIDField: {
		SGIDField:      AUDIT_COMPARE_SGID_TO_FSGID,
		GIDField:       AUDIT_COMPARE_GID_TO_FSGID,
		ObjectGIDField: AUDIT_COMPARE_FSGID_TO_OBJ_GID,
		EGIDField:      AUDIT_COMPARE_EGID_TO_FSGID,
	},
	GIDField: {
		EGIDField:      AUDIT_COMPARE_GID_TO_EGID,
		FSGIDField:     AUDIT_COMPARE_GID_TO_FSGID,
		ObjectGIDField: AUDIT_COMPARE_GID_TO_OBJ_GID,
		SGIDField:      AUDIT_COMPARE_GID_TO_SGID,
	},
	ObjectGIDField: {
		EGIDField:  AUDIT_COMPARE_EGID_TO_OBJ_GID,
		FSGIDField: AUDIT_COMPARE_FSGID_TO_OBJ_GID,
		GIDField:   AUDIT_COMPARE_GID_TO_OBJ_GID,
		SGIDField:  AUDIT_COMPARE_SGID_TO_OBJ_GID,
	},
	SGIDField: {
		FSGIDField:     AUDIT_COMPARE_SGID_TO_FSGID,
		GIDField:       AUDIT_COMPARE_GID_TO_SGID,
		ObjectGIDField: AUDIT_COMPARE_SGID_TO_OBJ_GID,
		EGIDField:      AUDIT_COMPARE_EGID_TO_SGID,
	},
}

var ReverseSyscall map[string]map[string]int

func buildReverseSyscallTable() {
	ReverseSyscall = make(map[string]map[string]int, len(auparse.Syscalls))

	for arch, syscallToName := range auparse.Syscalls {
		archTable := make(map[string]int, len(syscallToName))
		ReverseSyscall[arch] = archTable

		for syscallNum, syscallName := range syscallToName {
			archTable[syscallName] = syscallNum
		}
	}
}

var ReverseArch map[string]uint32

func buildReverseArchTable() {
	ReverseArch = make(map[string]uint32, len(auparse.ArchTable))

	for arch, name := range auparse.ArchTable {
		ReverseArch[name] = uint32(arch)
	}
}

func init() {
	buildReverseSyscallTable()
	buildReverseArchTable()
}
