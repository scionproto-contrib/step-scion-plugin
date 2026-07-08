// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package app provides helpers to report command output. All output is written
// to the command's stdout/stderr streams instead of the global os.Stdout, so
// that it can be captured in tests and redirected by the caller.
package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/mattn/go-isatty"
	"gopkg.in/yaml.v3"
)

// Command is the subset of *cobra.Command required to build a Report.
type Command interface {
	OutOrStdout() io.Writer
	ErrOrStderr() io.Writer
}

// ReportOptions holds the configurable behavior of a Report.
type ReportOptions struct {
	NoColor bool
}

// Option modifies ReportOptions.
type Option func(*ReportOptions)

// WithNoColor disables colorized output.
func WithNoColor(noColor bool) Option {
	return func(o *ReportOptions) {
		o.NoColor = noColor
	}
}

// Report writes command output to the command's stdout/stderr streams.
type Report struct {
	out     io.Writer
	err     io.Writer
	noColor bool
	outTerm bool
}

// NewReportForCmd creates a Report bound to the command's output streams.
func NewReportForCmd(cmd Command, opts ...Option) Report {
	var o ReportOptions
	for _, opt := range opts {
		opt(&o)
	}
	return Report{
		out:     cmd.OutOrStdout(),
		err:     cmd.ErrOrStderr(),
		noColor: o.NoColor,
		outTerm: isTerminal(cmd.OutOrStdout()),
	}
}

// OutWriter returns the raw stdout writer, e.g. for writing binary output.
func (r Report) OutWriter() io.Writer {
	return r.out
}

// OutIsTerminal reports whether stdout is a terminal.
func (r Report) OutIsTerminal() bool {
	return r.outTerm
}

func (r Report) Out(args ...interface{}) {
	fmt.Fprint(r.out, args...)
}

func (r Report) Outln(args ...interface{}) {
	r.Out(args...)
	r.Out("\n")
}

func (r Report) Outlnf(f string, args ...interface{}) {
	r.Outf(f+"\n", args...)
}

func (r Report) Outf(f string, args ...interface{}) {
	fmt.Fprintf(r.out, f, args...)
}

func (r Report) OutJSON(v any) error {
	if r.noColor || !r.outTerm {
		enc := json.NewEncoder(r.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return quick.Highlight(r.out, buf.String(), "json", "terminal256", "friendly")
}

func (r Report) OutYAML(v any) error {
	if r.noColor || !r.outTerm {
		enc := yaml.NewEncoder(r.out)
		enc.SetIndent(2)
		return enc.Encode(v)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return quick.Highlight(r.out, buf.String(), "yaml", "terminal256", "friendly")
}

func (r Report) Err(args ...interface{}) {
	fmt.Fprint(r.err, args...)
}

func (r Report) Errln(args ...interface{}) {
	r.Err(args...)
	r.Err("\n")
}

func (r Report) Errlnf(f string, args ...interface{}) {
	r.Errf(f+"\n", args...)
}

func (r Report) Errf(f string, args ...interface{}) {
	fmt.Fprintf(r.err, f, args...)
}

func (r Report) OutReplace(f string, args ...interface{}) {
	r.OutReplacef(f+"\n", args...)
}

func (r Report) OutReplacef(f string, args ...interface{}) {
	if r.outTerm {
		// move the cursor up one line and clear the line before printing
		// \033[F moves the cursor up one line
		// \033[K clears the line
		fmt.Fprintf(r.out, "\033[F\033[K"+f, args...)
		return
	}

	fmt.Fprintf(r.out, f, args...)
}

func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return isatty.IsTerminal(f.Fd())
	}
	return false
}
