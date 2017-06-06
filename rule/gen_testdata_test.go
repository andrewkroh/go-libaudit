// +build linux

package rule_test

import (
	"bufio"
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastic/go-libaudit"
	"gopkg.in/yaml.v2"
)

var update = flag.Bool("update", false, "update .golden.yml files")

// TestUpdateGoldenData generates new X.rules.golden.yml files the given
// X.rules files. The .rules files contain rules that are installed to the
// kernel using auditctl (auditd package must be installed). Then the binary
// representation of the rule from the kernel is requested and stored. Each
// rules and blob is stored in the YAML file as a test case.
//
// The kernel version and auditctl version used to generate the golden data
// are stored as comments in the YAML file header.
func TestUpdateGoldenData(t *testing.T) {
	if !*update {
		t.SkipNow()
	}

	rulesFiles, err := filepath.Glob("testdata/*.rules")
	if err != nil {
		t.Fatal(err)
	}

	for _, rulesFile := range rulesFiles {
		makeGoldenFile(t, rulesFile)
	}
}

func makeGoldenFile(t testing.TB, rulesFile string) {
	rules, err := ioutil.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}

	var testData GoldenData
	s := bufio.NewScanner(bytes.NewReader(rules))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		ruleData := auditctlExec(t, line)

		testData.Rules = append(testData.Rules, TestCase{
			Flags: line,
			Bytes: string(ruleData),
		})
	}

	yamlData, err := yaml.Marshal(testData)
	if err != nil {
		t.Fatal(err)
	}

	outFile, err := os.Create(rulesFile + ".golden.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()

	versionInfo := uname(t)
	outFile.WriteString("# ")
	outFile.WriteString(versionInfo)

	versionInfo = auditctlVersion(t)
	outFile.WriteString("# ")
	outFile.WriteString(versionInfo)
	outFile.WriteString("")

	outFile.Write(yamlData)
}

func uname(t testing.TB) string {
	output, err := exec.Command("uname", "-a").Output()
	if err != nil {
		t.Fatal(err)
	}

	return string(output)
}

func auditctlVersion(t testing.TB) string {
	output, err := exec.Command("auditctl", "-v").Output()
	if err != nil {
		t.Fatal(err)
	}

	return string(output)
}

func auditctlExec(t testing.TB, command string) []byte {
	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.DeleteRules()

	args := strings.Fields(command)
	_, err = exec.Command("auditctl", args...).Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			t.Fatalf("command=auditctl %v, stderr=%v, err=%v", command, string(exitError.Stderr), err)
		}
		t.Fatal(err)
	}

	rules, err := client.GetRules()
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule but got %d", len(rules))
	}

	return rules[0]
}
