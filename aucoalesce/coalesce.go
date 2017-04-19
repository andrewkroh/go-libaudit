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

// Package aucoalesce provides functions to coalesce compound audit messages
// into a single event.
package aucoalesce

import (
	"strings"

	"github.com/pkg/errors"

	"time"

	"github.com/elastic/go-libaudit/auparse"
)

type Event struct {
	Timestamp time.Time                `json:"@timestamp"`
	Sequence  uint32                   `json:"sequence"`
	Category  auparse.AuditEventType   `json:"category"`
	Type      auparse.AuditMessageType `json:"record_type"`
	Session   string                   `json:"session"`
	Action    string                   `json:"action"`
	Result    string                   `json:"result"`
	Actor     Actor                    `json:"actor"`
	Thing     Thing                    `json:"thing"`
	How       string                   `json:"how"`
	Key       string                   `json:"key,omitempty"`

	Data  map[string]string   `json:"data,omitempty"`
	Paths []map[string]string `json:"paths,omitempty"`
}

type Actor struct {
	Primary   string
	Secondary string
}

type Thing struct {
	Primary   string
	Secondary string
	What      string
}

// CoalesceMessages combines the given messages into a single event. It assumes
// that all the messages in the slice have the same timestamp and sequence
// number. An error is returned is msgs is empty or nil or only contains and EOE
// (end-of-event) message.
func CoalesceMessages(msgs []*auparse.AuditMessage) (map[string]interface{}, error) {
	msgs = filterEOE(msgs)

	switch len(msgs) {
	case 0:
		return nil, errors.New("messages is empty")
	case 1:
		return normalizeSimple(msgs[0])
	default:
		return normalizeCompound(msgs)
	}
}

func filterEOE(msgs []*auparse.AuditMessage) []*auparse.AuditMessage {
	out := msgs[:0]
	for _, msg := range msgs {
		if msg.RecordType != auparse.AUDIT_EOE {
			out = append(out, msg)
		}
	}
	return out
}
func normalizeCompound(msgs []*auparse.AuditMessage) (map[string]interface{}, error) {
	event := map[string]interface{}{
		"@timestamp": msgs[0].Timestamp,
		"sequence":   msgs[0].Sequence,
	}

	for _, msg := range msgs {
		data, err := msg.Data()
		if err != nil {
			continue
		}

		switch msg.RecordType {
		//case auparse.AUDIT_PROCTITLE:

		case auparse.AUDIT_PATH:
			addPathRecord(msg, event)
		case auparse.AUDIT_CWD:
			addCWDRecord(msg, event)
		case auparse.AUDIT_SYSCALL:
			rename("syscall", "name", data)
			delete(data, "items")
			addCommonFields(msg, event)
			fallthrough
		default:
			addRecord(msg, event)
		}
	}

	return event, nil
}

func normalizeSimple(msg *auparse.AuditMessage) (map[string]interface{}, error) {
	event := map[string]interface{}{
		"@timestamp": msg.Timestamp,
		"sequence":   msg.Sequence,
	}
	addCommonFields(msg, event)
	addRecord(msg, event)
	return event, nil
}

func addCommonFields(msg *auparse.AuditMessage, event map[string]interface{}) {
	event["category"] = auparse.GetAuditEventType(msg.RecordType).String()

	data, err := msg.Data()
	if err != nil {
		return
	}

	if auid, found := data["auid"]; found {
		event["auid"] = auid
		delete(data, "auid")
	}

	if ses, found := data["ses"]; found {
		event["session"] = ses
		delete(data, "ses")
	}

	if result, found := data["result"]; found {
		event["result"] = result
		delete(data, "result")
	}
}

func addRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	recordType := strings.ToLower(msg.RecordType.String())
	data, _ := msg.Data()
	event[recordType] = data
}

func addPathRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	paths, ok := event["path"].([]map[string]string)
	if !ok {
		paths = make([]map[string]string, 0, 1)
	}

	data, _ := msg.Data()
	paths = append(paths, data)
	event["path"] = paths
}

func addCWDRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	data, _ := msg.Data()
	cwd, found := data["cwd"]
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
