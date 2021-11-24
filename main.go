package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/vuln/client"
)

func keys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// parseDeps parses the output of "go mod graph" and returns unique list of dependencies
func parseDeps(r io.Reader) ([]string, error) {
	deps := make(map[string]bool) // use map for unique
	s := bufio.NewScanner(r)
	lnum := 0
	for s.Scan() {
		lnum++
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		// gopkg.in/yaml.v2@v2.4.0 gopkg.in/check.v1@v0.0.0-20161208181325-20d25e280405
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%d: bad line: %q", lnum, line)
		}

		// gopkg.in/yaml.v2@v2.4.0 -> gopkg.in/yaml.v2
		i := strings.Index(fields[1], "@")
		if i == -1 {
			return nil, fmt.Errorf("%d: missing version: %q", lnum, line)
		}
		deps[fields[1][:i]] = true
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return keys(deps), nil
}

func loadDeps() ([]string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("go", "mod", "graph")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return parseDeps(&buf)
}

func main() {
	// support --help
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: vuln")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: wrong number of arguments")
		os.Exit(1)
	}

	deps, err := loadDeps()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: can't load dependencies - %s", err)
		os.Exit(1)
	}

	sources := []string{
		"https://storage.googleapis.com/go-vulndb",
	}
	c, err := client.NewClient(sources, client.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: can't create client - %s", err)
		os.Exit(1)
	}
	ctx := context.Background()

	ok := true
	for _, pkg := range deps {
		es, err := c.GetByModule(ctx, pkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: can't get data for %q - %s", pkg, err)
			os.Exit(1)
		}

		for _, e := range es {
			if e.Withdrawn != nil {
				continue
			}
			ok = false
			fmt.Printf("\n%s: %s: %s", pkg, e.ID, e.Details)
			for _, ref := range e.References {
				fmt.Println(ref.URL)
			}
		}
	}

	if !ok {
		os.Exit(1)
	}
}
