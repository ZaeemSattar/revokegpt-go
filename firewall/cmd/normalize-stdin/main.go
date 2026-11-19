// Command normalize-stdin reads one raw request target per line on stdin and writes one JSON
// result per line on stdout, in the shape of the reference normalizePath:
//
//	{"ok":true,"path":"/a","collapsed":"/a"}
//	{"ok":false,"reason":"non-canonical","detail":"encoded-separator"}
//
// A line is the target's bytes up to the newline (a "\r" before it is part of the target, and a
// raw control character makes the target invalid). It exists for the cross-port differential.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	firewall "github.com/ZaeemSattar/revokegpt-go/firewall"
)

type okResult struct {
	OK        bool   `json:"ok"`
	Path      string `json:"path"`
	Collapsed string `json:"collapsed"`
}

type errResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func encode(raw string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	n := firewall.Normalize(raw)
	var err error
	if n.OK {
		err = enc.Encode(okResult{OK: true, Path: n.Path, Collapsed: n.Collapsed})
	} else {
		err = enc.Encode(errResult{OK: false, Reason: n.Reason, Detail: n.Detail})
	}
	return buf.Bytes(), err // Encode ends the value with a newline
}

func run(in io.Reader, out io.Writer) error {
	r := bufio.NewReaderSize(in, 1<<16)
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 || err == nil {
			if n := len(line); n > 0 && line[n-1] == '\n' {
				line = line[:n-1]
			}
			b, eerr := encode(line)
			if eerr != nil {
				return eerr
			}
			if _, werr := w.Write(b); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "normalize-stdin:", err)
		os.Exit(1)
	}
}
