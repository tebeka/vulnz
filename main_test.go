package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var graphText = `
github.com/tebeka/vulnz golang.org/x/mod@v0.4.2
github.com/tebeka/vulnz golang.org/x/vuln@v0.0.0-20211122183936-4641d369f3e9
github.com/tebeka/vulnz golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1
golang.org/x/mod@v0.4.2 golang.org/x/crypto@v0.0.0-20191011191535-87dc89f01550
golang.org/x/mod@v0.4.2 golang.org/x/tools@v0.0.0-20191119224855-298f0cb1881e
golang.org/x/mod@v0.4.2 golang.org/x/xerrors@v0.0.0-20191011141410-1b5146add898
`

func TestParseDeps(t *testing.T) {
	require := require.New(t)
	r := strings.NewReader(graphText)
	deps, err := parseDeps(r)
	require.NoError(err)
	expected := []string{
		"golang.org/x/mod",
		"golang.org/x/vuln",
		"golang.org/x/xerrors",
		"golang.org/x/crypto",
		"golang.org/x/tools",
	}
	require.ElementsMatch(expected, deps)
}
