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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/pkg/errors"
)

// modeBlockDevice is the file mode bit representing block devices. This OS
// package does not have a constant defined for this.
const modeBlockDevice = 060000

type Event struct {
	Timestamp time.Time                `json:"@timestamp"`
	Sequence  uint32                   `json:"sequence"`
	Category  auparse.AuditEventType   `json:"category"`
	Type      auparse.AuditMessageType `json:"record_type"`
	Result    string                   `json:"result,omitempty"`
	Session   string                   `json:"session"`
	Actor     Actor                    `json:"actor"`
	Thing     Thing                    `json:"thing,omitempty"`
	Action    string                   `json:"action,omitempty"`
	How       string                   `json:"how,omitempty"`
	Key       string                   `json:"key,omitempty"`

	Data   map[string]string   `json:"data,omitempty"`
	Paths  []map[string]string `json:"paths,omitempty"`
	Socket map[string]string   `json:"socket,omitempty"`

	Warnings []error `json:"-"`
}

type Actor struct {
	Primary    string            `json:"primary,omitempty"`
	Secondary  string            `json:"secondary,omitempty"`
	Attributes map[string]string `json:"attrs,omitempty"`   // Other identify data like euid, suid, fsuid, gid, egid, sgid, fsgid.
	SELinux map[string]string    `json:"selinux,omitempty"` // SELinux labels.
}

type Thing struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
	What      string `json:"what,omitempty"`
	SELinux   map[string]string `json:"selinux,omitempty"`
}

// ResolveIDs translates all uid and gid values to their associated names.
func ResolveIDs(event *Event) {
	if v := userLookup.LookupUID(event.Actor.Primary); v != "" {
		event.Actor.Primary = v
	}
	if v := userLookup.LookupUID(event.Actor.Secondary); v != "" {
		event.Actor.Secondary = v
	}
	for key, id := range event.Actor.Attributes {
		if strings.HasSuffix(key, "uid") {
			if v := userLookup.LookupUID(id); v != "" {
				event.Actor.Attributes[key] = v
			}
		} else if strings.HasSuffix(key, "gid") {
			if v := groupLookup.LookupGID(id); v != "" {
				event.Actor.Attributes[key] = v
			}
		}
	}
	for _, path := range event.Paths {
		for key, id := range path {
			if strings.HasSuffix(key, "uid") {
				if v := userLookup.LookupUID(id); v != "" {
					path[key] = v
				}
			} else if strings.HasSuffix(key, "gid") {
				if v := groupLookup.LookupGID(id); v != "" {
					path[key] = v
				}
			}
		}
	}
}

// CoalesceMessages combines the given messages into a single event. It assumes
// that all the messages in the slice have the same timestamp and sequence
// number. An error is returned is msgs is empty or nil or only contains and EOE
// (end-of-event) message.
func CoalesceMessages(msgs []*auparse.AuditMessage) (*Event, error) {
	msgs = filterEOE(msgs)

	var event *Event
	var err error
	switch len(msgs) {
	case 0:
		return nil, errors.New("messages is empty")
	case 1:
		event, err = normalizeSimple(msgs[0])
	default:
		event, err = normalizeCompound(msgs)
	}

	if event != nil {
		applyNormalization(event)
	}

	return event, err
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

func normalizeCompound(msgs []*auparse.AuditMessage) (*Event, error) {
	var special, syscall *auparse.AuditMessage
	for i, msg := range msgs {
		if i == 0 && msg.RecordType != auparse.AUDIT_SYSCALL {
			special = msg
			continue
		}
		if msg.RecordType == auparse.AUDIT_SYSCALL {
			syscall = msg
			break
		}
	}
	if syscall == nil {
		// All compound records have syscall messages.
		return nil, errors.New("missing syscall message in compound event")
	}

	event := newEvent(special, syscall)

	for _, msg := range msgs {
		switch msg.RecordType {
		case auparse.AUDIT_SYSCALL:
			delete(event.Data, "items")
		case auparse.AUDIT_PATH:
			addPathRecord(msg, event)
		case auparse.AUDIT_SOCKADDR:
			data, _ := msg.Data()
			event.Socket = data
		default:
			addFieldsToEvent(msg, event)
		}
	}

	return event, nil
}

func normalizeSimple(msg *auparse.AuditMessage) (*Event, error) {
	return newEvent(msg, nil), nil
}

func newEvent(msg *auparse.AuditMessage, syscall *auparse.AuditMessage) *Event {
	if msg == nil {
		msg = syscall
	}
	event := &Event{
		Timestamp: msg.Timestamp,
		Sequence:  msg.Sequence,
		Category:  auparse.GetAuditEventType(msg.RecordType),
		Type:      msg.RecordType,
		Data:      make(map[string]string, 10),
	}

	if syscall != nil {
		msg = syscall
	}

	data, err := msg.Data()
	if err != nil {
		event.Warnings = append(event.Warnings, err)
		return event
	}

	if result, found := data["result"]; found {
		event.Result = result
		delete(data, "result")
	} else {
		event.Result = "unknown"
	}

	if ses, found := data["ses"]; found {
		event.Session = ses
		delete(data, "ses")
	}

	if auid, found := data["auid"]; found {
		event.Actor.Primary = auid
		//delete(data, "auid")
	}

	if uid, found := data["uid"]; found {
		event.Actor.Secondary = uid
		//delete(data, "uid")
	}

	if key, found := data["key"]; found {
		event.Key = key
		delete(data, "key")
	}

	for k, v := range data {
		if strings.HasSuffix(k, "uid") || strings.HasSuffix(k, "gid") {
			addActorAttribute(k, v, event)
		} else if strings.HasPrefix(k, "subj_") {
			addActorSELinux(k[5:], v, event)
		} else {
			event.Data[k] = v
		}
	}

	return event
}

func addActorAttribute(key, value string, event *Event) error {
	if event.Actor.Attributes == nil {
		event.Actor.Attributes = map[string]string{}
	}

	event.Actor.Attributes[key] = value
	return nil
}

func addActorSELinux(key, value string, event *Event) error {
	if event.Actor.SELinux == nil {
		event.Actor.SELinux = map[string]string{}
	}

	event.Actor.SELinux[key] = value
	return nil
}

func addThingSELinux(key, value string, event *Event) error {
	if event.Thing.SELinux == nil {
		event.Thing.SELinux = map[string]string{}
	}

	event.Thing.SELinux[key] = value
	return nil
}

func addPathRecord(path *auparse.AuditMessage, event *Event) {
	data, err := path.Data()
	if err != nil {
		event.Warnings = append(event.Warnings, err)
		return
	}

	event.Paths = append(event.Paths, data)
}

func addFieldsToEvent(msg *auparse.AuditMessage, event *Event) {
	data, err := msg.Data()
	if err != nil {
		event.Warnings = append(event.Warnings, err)
		return
	}

	for k, v := range data {
		if _, found := event.Data[k]; found {
			event.Warnings = append(event.Warnings, errors.Errorf("duplicate key (%v) from %v message", k, msg.RecordType))
			continue
		}
		event.Data[k] = v
	}
}

func setHowDefaults(event *Event) {
	exe, found := event.Data["exe"]
	if !found {
		// Fallback to comm.
		exe, found = event.Data["comm"]
		if !found {
			return
		}
	}
	event.How = exe

	switch {
	case strings.HasPrefix(exe, "/usr/bin/python"),
		strings.HasPrefix(exe, "/usr/bin/sh"),
		strings.HasPrefix(exe, "/usr/bin/bash"),
		strings.HasPrefix(exe, "/usr/bin/perl"):
	default:
		return
	}

	// It's probably some kind of interpreted script so use "comm".
	comm, found := event.Data["comm"]
	if !found {
		return
	}
	event.How = comm
}

func applyNormalization(event *Event) {
	setHowDefaults(event)

	var norm *Normalization
	if event.Type == auparse.AUDIT_SYSCALL {
		syscall := event.Data["syscall"]
		norm = syscallNorms[syscall]
	} else {
		norm = recordTypeNorms[event.Type.String()]
	}
	if norm == nil {
		event.Warnings = append(event.Warnings, errors.New("no normalization found for event"))
		return
	}

	event.Action = norm.Action

	switch norm.Object.What {
	case "file", "filesystem":
		event.Thing.What = norm.Object.What
		setFileObject(event, norm.Object.PathIndex)
	case "socket":
		event.Thing.What = norm.Object.What
		setSocketObject(event)
	default:
		event.Thing.What = norm.Object.What
	}

	if len(norm.Subject.PrimaryFieldName.Values) > 0 {
		var err error
		for _, subjKey := range norm.Subject.PrimaryFieldName.Values {
			if err = setSubjectPrimary(subjKey, event); err == nil {
				break
			}
		}
		if err != nil {
			event.Warnings = append(event.Warnings, errors.Errorf("failed to set subject primary using keys=%v because they were not found", norm.Subject.PrimaryFieldName.Values))
		}
	}

	if len(norm.Subject.SecondaryFieldName.Values) > 0 {
		var err error
		for _, subjKey := range norm.Subject.SecondaryFieldName.Values {
			if err = setSubjectSecondary(subjKey, event); err == nil {
				break
			}
		}
		if err != nil {
			event.Warnings = append(event.Warnings, errors.Errorf("failed to set subject secondary using keys=%v because they were not found", norm.Subject.SecondaryFieldName.Values))
		}
	}

	if len(norm.Object.PrimaryFieldName.Values) > 0 {
		var err error
		for _, objKey := range norm.Object.PrimaryFieldName.Values {
			if err = setObjectPrimary(objKey, event); err == nil {
				break
			}
		}
		if err != nil {
			event.Warnings = append(event.Warnings, errors.Errorf("failed to set object primary using keys=%v because they were not found", norm.Object.PrimaryFieldName.Values))
		}
	}

	if len(norm.Object.SecondaryFieldName.Values) > 0 {
		var err error
		for _, objKey := range norm.Object.SecondaryFieldName.Values {
			if err = setObjectSecondary(objKey, event); err == nil {
				break
			}
		}
		if err != nil {
			event.Warnings = append(event.Warnings, errors.Errorf("failed to set object secondary using keys=%v because they were not found", norm.Object.SecondaryFieldName.Values))
		}
	}

	if len(norm.How.Values) > 0 {
		var err error
		for _, howKey := range norm.How.Values {
			if err = setHow(howKey, event); err == nil {
				break
			}
		}
		if err != nil {
			event.Warnings = append(event.Warnings, errors.Errorf("failed to set how using keys=%v because they were not found", norm.How.Values))
		}
	}
}

func getValue(key string, event *Event) (string, bool) {
	value, found := event.Data[key]
	if !found {
		value, found = event.Actor.Attributes[key]
	}
	return value, found
}

func setHow(key string, event *Event) error {
	value, found := getValue(key, event)
	if !found {
		return errors.Errorf("failed to set how value: key '%v' not found", key)
	}

	event.How = value
	return nil
}

func setSubjectPrimary(key string, event *Event) error {
	value, found := getValue(key, event)
	if !found {
		return errors.Errorf("failed to set subject primary value: key '%v' not found", key)
	}

	event.Actor.Primary = value
	return nil
}

func setSubjectSecondary(key string, event *Event) error {
	value, found := getValue(key, event)
	if !found {
		return errors.Errorf("failed to set subject secondary value: key '%v' not found", key)
	}

	event.Actor.Secondary = value
	return nil
}

func setObjectPrimary(key string, event *Event) error {
	value, found := getValue(key, event)
	if !found {
		return errors.Errorf("failed to set object primary value: key '%v' not found", key)
	}

	event.Thing.Primary = value
	return nil
}

func setObjectSecondary(key string, event *Event) error {
	value, found := getValue(key, event)
	if !found {
		return errors.Errorf("failed to set object secondary value: key '%v' not found", key)
	}

	event.Thing.Secondary = value
	return nil
}

func setFileObject(event *Event, pathIndexHint int) error {
	if len(event.Paths) == 0 {
		return errors.New("path message not found")
	}

	var pathIndex int
	if len(event.Paths) > pathIndexHint {
		pathIndex = pathIndexHint
	}

	path := event.Paths[pathIndex]
	for _, p := range event.Paths[pathIndex:] {
		// Skip over PARENT and UNKNOWN types in case the path index was wrong.
		if nametype := p["nametype"]; nametype != "PARENT" && nametype != "UNKNOWN" {
			path = p
			break
		}
	}

	value, found := path["name"]
	if found {
		event.Thing.Primary = value
	}

	value, found = path["inode"]
	if found {
		event.Thing.Secondary = value
	}

	value, found = path["mode"]
	if found {
		mode, err := strconv.ParseUint(value, 8, 64)
		if err != nil {
			return errors.Wrap(err, "failed to parse file mode")
		}

		m := os.FileMode(mode)
		switch {
		case m.IsRegular():
			event.Thing.What = "file"
		case m.IsDir():
			event.Thing.What = "directory"
		case m&os.ModeCharDevice != 0:
			event.Thing.What = "character-device"
		case m&modeBlockDevice != 0:
			event.Thing.What = "block-device"
		case m&os.ModeNamedPipe != 0:
			event.Thing.What = "named-pipe"
		case m&os.ModeSymlink != 0:
			event.Thing.What = "symlink"
		case m&os.ModeSocket != 0:
			event.Thing.What = "socket"
		}
	}

	for k, v := range path {
		if strings.HasPrefix(k, "obj_") {
			addThingSELinux(k[4:], v, event)
		}
	}

	return nil
}

func setSocketObject(event *Event) error {
	value, found := event.Socket["addr"]
	if found {
		event.Thing.Primary = value
	} else {
		value, found = event.Socket["path"]
		if found {
			event.Thing.Primary = value
		}
	}

	value, found = event.Socket["port"]
	if found {
		event.Thing.Secondary = value
	}
	return nil
}
