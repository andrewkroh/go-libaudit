package libaudit

import (
	"sort"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/go-libaudit/auparse"
)

type sequenceNum uint64

type sequenceNumSlice []sequenceNum

func (p sequenceNumSlice) Len() int           { return len(p) }
func (p sequenceNumSlice) Less(i, j int) bool { return p[i] < p[j] }
func (p sequenceNumSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p sequenceNumSlice) Sort()              { sort.Sort(p) }

// Stream is implemented by the user of the Reassembler to handle reassembled
// audit data.
type Stream interface {
	// ReassemblyComplete notifies that a complete group of events has been
	// received and provides those events.
	ReassemblyComplete(msgs []*auparse.AuditMessage)

	// EventsLost notifies that some events were lost. This is based on gaps
	// in the sequence numbers of received messages. Lost events can be caused
	// by a slow receiver or because the kernel is configured to rate limit
	// events.
	EventsLost(count int)
}

type event struct {
	expireTime time.Time
	msgs       []*auparse.AuditMessage
	complete   bool
}

func (e *event) Add(msg *auparse.AuditMessage) {
	e.msgs = append(e.msgs, msg)

	if msg.RecordType == auparse.AUDIT_EOE {
		e.complete = true
	}
}

func (e *event) IsExpired() bool {
	return e.expireTime.After(time.Now())
}

type eventList struct {
	seqs    sequenceNumSlice
	events  map[sequenceNum]*event
	lastSeq sequenceNum
	maxSize int
	timeout time.Duration
}

func newEventList(maxSize int, timeout time.Duration) *eventList {
	return &eventList{
		seqs:    make([]sequenceNum, 0, maxSize+1),
		events:  make(map[sequenceNum]*event, maxSize+1),
		maxSize: maxSize,
		timeout: timeout,
	}
}

// Remove the first event (lowest sequence) in the list.
func (l *eventList) Remove() {
	if len(l.seqs) > 0 {
		seq := l.seqs[0]
		l.seqs = l.seqs[1:]
		delete(l.events, seq)
	}
}

// Clear removes all events from the list and returns the events and the number
// of list events.
func (l *eventList) Clear() ([]*event, int) {
	var lost int
	var seq sequenceNum
	var evicted []*event
	for {
		size := len(l.seqs)
		if size == 0 {
			break
		}

		// Get event.
		seq = l.seqs[0]
		event := l.events[seq]

		if l.lastSeq > 0 {
			lost += int(seq - l.lastSeq - 1)
		}
		l.lastSeq = seq
		evicted = append(evicted, event)
		l.Remove()
	}

	return evicted, lost
}

// Put a new message in the list.
func (l *eventList) Put(msg *auparse.AuditMessage) {
	seq := sequenceNum(msg.Sequence)
	e, found := l.events[seq]
	if !found {
		l.seqs = append(l.seqs, seq)
		l.seqs.Sort()

		e = &event{
			expireTime: time.Now(),
			msgs:       make([]*auparse.AuditMessage, 0, 4),
		}
		l.events[seq] = e
	}

	e.Add(msg)
}

func (l *eventList) CleanUp() ([]*event, int) {
	var lost int
	var seq sequenceNum
	var evicted []*event
	for {
		size := len(l.seqs)
		if size == 0 {
			break
		}

		// Get event.
		seq = l.seqs[0]
		event := l.events[seq]

		if event.complete || size > l.maxSize || event.IsExpired() {
			if l.lastSeq > 0 {
				lost += int(seq - l.lastSeq - 1)
			}
			l.lastSeq = seq
			evicted = append(evicted, event)
			l.Remove()
			continue
		}

		break
	}

	return evicted, lost
}

type Reassembler struct {
	// cache contains the in-flight event messages. Eviction occurs when an
	// event is completed via an EOE message, the cache reaches max size
	// (lowest sequence is evicted first), or an event expires base on time.
	list *eventList

	// stream is the callback interface used for delivering completed events.
	stream Stream
}

func NewReassembler(maxInFlight int, timeout time.Duration, stream Stream) (*Reassembler, error) {
	if stream == nil {
		return nil, errors.New("stream cannot be nil")
	}

	return &Reassembler{
		list:   newEventList(maxInFlight, timeout),
		stream: stream,
	}, nil
}

func (r *Reassembler) PushMessage(msg *auparse.AuditMessage) {
	if msg == nil {
		return
	}

	r.list.Put(msg)
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
}

func (r *Reassembler) Push(typ uint16, rawData []byte) error {
	msg, err := auparse.Parse(auparse.AuditMessageType(typ), string(rawData))
	if err != nil {
		return err
	}

	r.PushMessage(msg)
	return nil
}

func (r *Reassembler) Close() error {
	evicted, lost := r.list.Clear()
	r.callback(evicted, lost)
	return nil
}

func (r *Reassembler) callback(events []*event, lost int) {
	for _, e := range events {
		r.stream.ReassemblyComplete(e.msgs)
	}

	if lost > 0 {
		r.stream.EventsLost(lost)
	}
}
