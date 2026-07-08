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

package trc

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

// atMostOneInput is a cobra Args validator for commands that read a single
// input from a file argument or, when the argument is omitted, from standard
// input. It accepts zero or one argument, but rejects zero arguments when
// stdin is a terminal so the command does not hang waiting for interactive
// input.
func atMostOneInput(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("accepts at most 1 arg, received %d", len(args))
	}
	if len(args) == 0 && inputIsTerminal(cmd) {
		return errors.New("no input: provide a file argument or pipe it to stdin")
	}
	return nil
}

// inputFile returns the input file argument, defaulting to "-" (stdin) when no
// argument is given.
func inputFile(args []string) string {
	if len(args) == 0 {
		return "-"
	}
	return args[0]
}

// inputIsTerminal reports whether the command's stdin is a terminal.
func inputIsTerminal(cmd *cobra.Command) bool {
	f, ok := cmd.InOrStdin().(*os.File)
	return ok && isatty.IsTerminal(f.Fd())
}

// DecodeFromFile decodes a signed TRC from the provided file. If name is "-",
// the TRC is read from stdin.
func DecodeFromFile(name string, stdin io.Reader) (cppki.SignedTRC, error) {
	raw, err := app.ReadFileOrStdin(name, stdin)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	block, _ := pem.Decode(raw)
	if block != nil && block.Type == "TRC" {
		raw = block.Bytes
	}
	return cppki.DecodeSignedTRC(raw)
}

// addOutFileFlag registers the --out-file flag. When it is not set, the output
// is written to standard output.
func addOutFileFlag(flag *string, cmd *cobra.Command) {
	cmd.Flags().StringVar(flag, "out-file", "",
		"Output file. If not set, the output is written to stdout.")
}

// addFormatFlag registers the --format flag that selects the output encoding.
// It defaults to PEM.
func addFormatFlag(flag *string, cmd *cobra.Command) {
	cmd.Flags().StringVar(flag, "format", "pem", "Output format (der|pem)")
}

// writeOutput writes the DER encoded input to outFile, or to standard output if
// outFile is empty or "-". Unless format is "der", the bytes are PEM encoded
// with the given block type. Writing DER to a terminal is refused to avoid
// corrupting it. Progress messages are written to stderr so that they never
// pollute the payload on standard output.
func writeOutput(rep app.Report, outFile, format, pemType string, der []byte) error {
	var output []byte
	switch strings.ToLower(format) {
	case "pem":
		output = pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
		if output == nil {
			return errors.New("PEM encoding failed")
		}
	case "der":
		output = der
	default:
		return fmt.Errorf("format not supported: %s", format)
	}

	if outFile == "" || outFile == "-" {
		if strings.ToLower(format) == "der" && rep.OutIsTerminal() {
			return errors.New("refusing to write DER encoded bytes to tty")
		}
		_, err := rep.OutWriter().Write(output)
		return err
	}
	if err := os.WriteFile(outFile, output, 0o644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}
	rep.Errlnf("Successfully wrote %s", outFile)
	return nil
}
