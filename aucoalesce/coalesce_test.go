package aucoalesce

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/elastic/go-libaudit/auparse"
)

func logEvent(event map[string]interface{}) {
	out, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(out))
}

func TestCoalesceMessages(t *testing.T) {
	msgs := readMessages(t, "testdata/execve.log")

	event, err := CoalesceMessages(msgs)
	if err != nil {
		t.Fatal(err)
	}
	logEvent(event)
}

func readMessages(t testing.TB, name string) []*auparse.AuditMessage {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var msgs []*auparse.AuditMessage

	// Read logs and parse events.
	s := bufio.NewScanner(bufio.NewReader(f))
	for s.Scan() {
		line := s.Text()
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			t.Fatal("invalid message:", line)
		}

		msgs = append(msgs, msg)
	}

	return msgs
}
