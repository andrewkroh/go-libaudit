package aucoalesce

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadNormalizationConfig(t *testing.T) {
	b, err := ioutil.ReadFile("normalizations.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	n, err := LoadNormalizationConfig(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	for _, v := range n.Normalizations {
		fmt.Printf("%+v\n", v)
	}
}

func TestNormInit(t *testing.T) {
	fmt.Printf("%+v\n", syscallNorms)
	fmt.Printf("%+v\n", recordTypeNorms)
}
