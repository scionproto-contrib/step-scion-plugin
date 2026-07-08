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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

func NewExtractCmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract the payload or certificates from a signed TRC",
		Long: `Extract parts of a signed TRC.

A signed TRC bundles the TRC payload together with the voting and root
certificates it authorizes. The subcommands extract these parts:

  - payload:       the TRC payload, e.g. to re-sign or inspect it
  - certificates:  the bundled certificates as a PEM bundle`,
	}
	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		newExtractPayload(joined),
		newExtractCertificates(joined),
	)
	return cmd
}

func newExtractPayload(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		format string
	}

	cmd := &cobra.Command{
		Use:     "payload [trc-file]",
		Aliases: []string{"pld"},
		Short:   "Extract the payload from a signed TRC",
		Example: fmt.Sprintf(`  %[1]s payload ISD1-B1-S1.trc > ISD1-B1-S1.pld.pem
  %[1]s payload --format der ISD1-B1-S1.trc > ISD1-B1-S1.pld.der`,
			pather.CommandPath()),
		Long: `Extract the payload from a signed TRC.

The input is a signed TRC, read from the given file or from standard input when
the argument is omitted or "-". The payload is written to standard output, or
to the file given with --out-file, encoded as PEM (default) or DER (--format).

The DER payload is the ASN.1 structure that is covered by the signatures. To
inspect it with openssl:

    openssl asn1parse -inform DER -i -in ISD1-B1-S1.pld.der`,
		Args: atMostOneInput,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			signed, err := DecodeFromFile(inputFile(args), cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to load signed TRC: %w", err)
			}
			return writeOutput(app.NewReportForCmd(cmd), flags.out, flags.format,
				"TRC PAYLOAD", signed.TRC.Raw)
		},
	}

	addOutFileFlag(&flags.out, cmd)
	addFormatFlag(&flags.format, cmd)
	return cmd
}

func newExtractCertificates(pather command.Pather) *cobra.Command {
	var flags struct {
		out   string
		ias   []string
		types []string
	}

	cmd := &cobra.Command{
		Use:     "certificates [trc-file]",
		Aliases: []string{"certs", "certificate", "cert"},
		Short:   "Extract the certificates bundled in a TRC",
		Example: fmt.Sprintf(`  %[1]s certificates ISD1-B1-S1.trc > ISD1-B1-S1.certs.pem
  %[1]s certificates --type cp-root ISD1-B1-S1.trc
  %[1]s certificates --subject.isd-as 1-ff00:0:110 ISD1-B1-S1.trc`,
			pather.CommandPath()),
		Long: `Extract the certificates bundled in a TRC as a PEM bundle.

The input is a signed TRC, read from the given file or from standard input when
the argument is omitted or "-". The certificates are written, in TRC order, to
standard output or to the file given with --out-file.

The selection can be narrowed with repeatable filters:

  - --type:          keep only certificates of the given type
                     (` + strings.Join(getTypes(), ", ") + `)
  - --subject.isd-as: keep only certificates with the given subject ISD-AS

Beware: the certificates are not verified. Verify the TRC with 'trc verify'
before relying on them.`,
		Args: atMostOneInput,
		RunE: func(cmd *cobra.Command, args []string) error {
			types := make(map[cppki.CertType]bool)
			for _, t := range flags.types {
				if t == "any" {
					types = nil // No filter, all types are included.
					break
				}
				typ, ok := certTypes[t]
				if !ok {
					return fmt.Errorf("unknown certificate type %q, valid types are: %s",
						t, strings.Join(getTypes(), ", "))
				}
				types[typ] = true
			}

			ias := make(map[addr.IA]bool)
			for _, v := range flags.ias {
				ia, err := addr.ParseIA(v)
				if err != nil {
					return fmt.Errorf("invalid ISD-AS %q: %w", v, err)
				}
				ias[ia] = true
			}

			cmd.SilenceUsage = true

			rep := app.NewReportForCmd(cmd)
			if err := runExtractCertificates(rep, cmd.InOrStdin(), inputFile(args), flags.out, types, ias); err != nil {
				return err
			}
			if flags.out != "" && flags.out != "-" {
				rep.Errlnf("Successfully extracted certificates at %s", flags.out)
			}
			return nil
		},
	}

	addOutFileFlag(&flags.out, cmd)

	cmd.Flags().StringSliceVar(&flags.ias, "subject.isd-as", nil,
		"Filter certificates by ISD-AS of the subject (e.g., 1-ff00:0:110)",
	)
	cmd.Flags().StringSliceVar(&flags.types, "type", nil,
		"Filter certificates by type ("+strings.Join(getTypes(), "|")+")",
	)
	return cmd
}

func runExtractCertificates(
	rep app.Report, stdin io.Reader, in, out string,
	types map[cppki.CertType]bool, ias map[addr.IA]bool,
) error {
	signed, err := DecodeFromFile(in, stdin)
	if err != nil {
		return fmt.Errorf("failed to load signed TRC: %w", err)
	}
	certs := make([]*x509.Certificate, 0, len(signed.TRC.Certificates))

	// Filter the certificates based on the user input.
	for _, cert := range signed.TRC.Certificates {
		// Check certificate type
		{
			typ, err := cppki.ValidateCert(cert)
			if err != nil {
				return fmt.Errorf("invalid certificate %s: %w", cert.Subject.CommonName, err)
			}
			if len(types) > 0 && !types[typ] {
				continue
			}
		}

		// Check certificate ISD-AS
		{
			ia, err := cppki.ExtractIA(cert.Subject)
			if err != nil {
				return fmt.Errorf("failed to extract ISD-AS from certificate %s: %w",
					cert.Subject.CommonName, err)
			}
			if len(ias) > 0 && !ias[ia] {
				continue
			}
		}
		certs = append(certs, cert)
	}

	return writeBundle(rep, out, certs)
}

func writeBundle(rep app.Report, out string, certs []*x509.Certificate) error {
	o := rep.OutWriter()
	if out != "" && out != "-" {
		f, err := os.Create(out)
		if err != nil {
			return fmt.Errorf("unable to create file: %w", err)
		}
		defer f.Close()
		o = f
	}
	for i, cert := range certs {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(o, &block); err != nil {
			return fmt.Errorf("unable to encode certificate %d: %w", i, err)
		}
	}
	return nil
}

var certTypes = map[string]cppki.CertType{
	cppki.Root.String():      cppki.Root,
	cppki.CA.String():        cppki.CA,
	cppki.AS.String():        cppki.AS,
	cppki.Sensitive.String(): cppki.Sensitive,
	cppki.Regular.String():   cppki.Regular,
}

func getTypes() []string {
	options := make([]string, 0, len(certTypes)+1)
	for k := range certTypes {
		options = append(options, k)
	}
	options = append(options, "any")
	slices.Sort(options)
	return options
}
