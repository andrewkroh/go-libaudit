package ragel

// Parser is generated from a ragel state machine using the following command:
//go:generate ragel -Z -G2 auditd.go.rl -o auditd.go
// go:generate goimports -l -w auditd.go

// An SVG rendering of the state machine can be viewed by opening auditd.svg in
// Chrome / Firefox.
//go:generate ragel -V -M audit_msg -p auditd.go.rl -o auditd.dot
//go:generate dot -T svg auditd.dot -o auditd.svg

type Message struct {
	Type      string
	TypeID    int32
	Timestamp string
	Sequence  string
	Values    map[string]string
	Message   string
	Original  string
}

func (m *Message) Unpack(data string) error {
	m.Original = data
	err := m.unpack(data)
	return err
}
