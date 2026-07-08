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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

func NewFormatCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		format string
		force  bool
	}
	cmd := &cobra.Command{
		Use:   "format [trc-file]",
		Short: "Convert a TRC or TRC payload between PEM and DER",
		Example: fmt.Sprintf(`  %[1]s format ISD1-B1-S1.trc.der
  %[1]s format --format der ISD1-B1-S1.pld > ISD1-B1-S1.pld.der`,
			pather.CommandPath(),
		),
		Long: `Convert a TRC or TRC payload between the PEM and DER encodings.

The input is read from the given file, or from standard input when the argument
is omitted or "-". The input encoding is detected automatically. Whether the
input is a TRC or a TRC payload is preserved: the PEM block type is 'TRC' for a
signed TRC and 'TRC PAYLOAD' for a payload.

The result is written to standard output, or to the file given with --out-file.
Use --format to select the output encoding (pem, the default, or der), and
--force to overwrite an existing output file.

Writing DER to a terminal is refused, because the raw bytes may corrupt it;
redirect standard output to a file or use --out-file instead.`,
		Args: atMostOneInput,
		RunE: func(cmd *cobra.Command, args []string) error {
			origFormat := flags.format
			flags.format = strings.ToLower(flags.format)
			if flags.format != "der" && flags.format != "pem" {
				return fmt.Errorf("format not supported: %s", origFormat)
			}
			if flags.out != "" {
				if err := checkDirExists(filepath.Dir(flags.out)); err != nil {
					return fmt.Errorf("checking that output directory exists: %w", err)
				}
			}
			cmd.SilenceUsage = true
			rep := app.NewReportForCmd(cmd)

			raw, err := app.ReadFileOrStdin(inputFile(args), cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			dec, err := decodeTRCorPayload(raw)
			if err != nil {
				return err
			}
			var output []byte
			var pemHeader string
			if dec.Signed != nil {
				output = dec.Signed.Raw
				pemHeader = "TRC"
			} else {
				output = dec.TRC.Raw
				pemHeader = "TRC PAYLOAD"
			}

			// Encode to PEM if not requested DER.
			if flags.format != "der" {
				output = pem.EncodeToMemory(&pem.Block{
					Type:  pemHeader,
					Bytes: output,
				})
				if output == nil {
					panic("PEM encoding failed")
				}
			}

			if flags.out == "" {
				if flags.format == "der" && rep.OutIsTerminal() {
					return fmt.Errorf("refusing to write DER encoded bytes to tty")
				}
				_, err := rep.OutWriter().Write(output)
				return err
			}

			err = writeFile(flags.out, output, 0644, flags.force)
			if err != nil {
				return fmt.Errorf("writing to output file: %w", err)
			}
			rep.Errlnf("Transformation successfully written to %q", flags.out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&flags.out, "out-file", "o", "",
		"The path to write the transformation TRC or TRC payload. "+
			"If not set, the output is written to stdout.",
	)
	addFormatFlag(&flags.format, cmd)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwriting existing output file",
	)
	return cmd
}
