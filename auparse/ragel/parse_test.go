package ragel

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestUnpack(t *testing.T) {
	inputs, err := filepath.Glob("testdata/*.txt")
	require.NoError(t, err)

	for _, path := range inputs {
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, ".txt")

		t.Run(name, func(t *testing.T) {
			data, err := ioutil.ReadFile(path)
			require.NoError(t, err)
			data = bytes.TrimSpace(data)

			var m Message
			err = m.Unpack(string(data))
			require.NoError(t, err)

			outData, err := yaml.Marshal(m)
			require.NoError(t, err)

			require.NoError(t, ioutil.WriteFile(path+".golden", outData, 0644))
		})
	}
}

func TestOldDataUnpack(t *testing.T) {
	inputs, err := filepath.Glob("../testdata/*.log")
	require.NoError(t, err)
	var msgs []string
	for _, path := range inputs {
		data, err := ioutil.ReadFile(path)
		require.NoError(t, err)
		lines := strings.Split(string(data), "\n")
		msgs = append(msgs, lines...)
	}

	var parsed []Message
	success := 0
	for _, msg := range msgs {
			msg = strings.TrimSpace(msg)
			if msg == "" {
				continue
			}
			var m Message
			err = m.Unpack(msg)
			require.NoError(t, err, "success=%d, %s", success, msg)
		    success++
		parsed = append(parsed, m)
	}

	outData, err := yaml.Marshal(parsed)
	require.NoError(t, err)
	require.NoError(t, ioutil.WriteFile("testdata/old.golden", outData, 0644))
}

func TestHexNumStringValue(t *testing.T) {
	t.Run("hex", func(t *testing.T) {
		var m Message
		err := m.unpackData("ABCDEF", Value)
		require.NoError(t, err)
	})
	t.Run("num", func(t *testing.T) {
		var m Message
		err := m.unpackData("123", Value)
		require.NoError(t, err)
	})
	t.Run("string", func(t *testing.T) {
		var m Message
		err := m.unpackData("ab:cd:ef", Value)
		require.NoError(t, err)
	})
	t.Run("dq", func(t *testing.T) {
		var m Message
		err := m.unpackData(`"123"`, Value)
		require.NoError(t, err)
	})
	t.Run("sq", func(t *testing.T) {
		var m Message
		err := m.unpackData(`'123'`, Value)
		require.NoError(t, err)
	})
}