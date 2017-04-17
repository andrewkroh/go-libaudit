package aucoalesce

import (
	"strings"

	"github.com/elastic/go-libaudit/auparse"

	"github.com/pkg/errors"
)

func coalesceMessages(msgs []*auparse.AuditMessage) (map[string]interface{}, error) {
	if len(msgs) == 0 {
		return nil, errors.New("messages is empty")
	}

	event := map[string]interface{}{
		"@timestamp": msgs[0].Timestamp,
		"sequence":   msgs[0].Sequence,
	}

	for _, msg := range msgs {
		switch msg.RecordType {
		default:
			addRecord(msg, event)
		case auparse.AUDIT_PATH:
			addPathRecord(msg, event)
		case auparse.AUDIT_CWD:
			addCWDRecord(msg, event)
		case auparse.AUDIT_SYSCALL:
			rename("syscall", "name", msg.Data)
			delete(msg.Data, "items")
			addRecord(msg, event)
		}
	}

	return event, nil
}

func addRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	recordType := strings.ToLower(msg.RecordType.String())
	event[recordType] = msg.Data
}

func addPathRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	paths, ok := event["path"].([]map[string]string)
	if !ok {
		paths = make([]map[string]string, 0, 1)
	}

	paths = append(paths, msg.Data)
	event["path"] = paths
}

func addCWDRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	cwd, found := msg.Data["cwd"]
	if !found {
		return
	}

	event["cwd"] = cwd
}

func rename(old, new string, event map[string]string) {
	value, found := event[old]
	if found {
		delete(event, old)
		event[new] = value
	}
}
