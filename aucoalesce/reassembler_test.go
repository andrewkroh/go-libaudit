package aucoalesce

import (
	"bufio"
	"os"
	"testing"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/stretchr/testify/assert"
	"time"
)

type testStream struct {
	events     [][]*auparse.AuditMessage
	dropped    int
}

func (s *testStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	s.events = append(s.events, msgs)
}

func (s *testStream) EventsLost(count int) { s.dropped += count }

func TestReassembler(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		testReassembler(t, "testdata/normal.log", &results{
			dropped:    0,
			outOfOrder: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("lost_messages", func(t *testing.T) {
		testReassembler(t, "testdata/lost_messages.log", &results{
			dropped:    9,
			outOfOrder: 0,
			events: []eventMeta{
				{seq: 49, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("out_of_order", func(t *testing.T) {
		testReassembler(t, "testdata/out_of_order.log", &results{
			dropped:    0,
			outOfOrder: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})
}

type eventMeta struct {
	seq   int
	count int
}

type results struct {
	dropped    int
	outOfOrder int
	events     []eventMeta
}

func testReassembler(t testing.TB, file string, expected *results) {
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stream := &testStream{events: make([][]*auparse.AuditMessage, 0, 10)}
	reassmbler, err := NewReassembler(5, 2 * time.Second, stream)
	if err != nil {
		t.Fatal(err)
	}

	// Read logs and parse events.
	s := bufio.NewScanner(bufio.NewReader(f))
	for s.Scan() {
		line := s.Text()
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			t.Log("invalid message:", line)
			continue
		}

		reassmbler.Push(msg)
	}

	// Flush any pending messages.
	if err := reassmbler.Close(); err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, expected.dropped, stream.dropped, "dropped messages")
	for i, expectedEvent := range expected.events {
		if len(stream.events) <= i {
			t.Fatal("less events received than expected")
		}

		for _, msg := range stream.events[i] {
			assert.Equal(t, expectedEvent.seq, msg.Sequence, "sequence number")
		}
		assert.Equal(t, expectedEvent.count, len(stream.events[i]), "message count")
	}
}
