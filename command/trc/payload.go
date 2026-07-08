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
	_ "embed"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

func NewPayloadCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		tmpl   string
		pred   string
		format string
	}

	cmd := &cobra.Command{
		Use:   "payload",
		Short: "Generate a TRC payload from a template",
		Example: fmt.Sprintf(`  %[1]s payload --template ISD1-B1-S1.toml > ISD1-B1-S1.pld.pem
  %[1]s payload --template ISD1-B1-S2.toml --predecessor ISD1-B1-S1.trc > ISD1-B1-S2.pld.pem`,
			pather.CommandPath()),
		Long: `Generate a TRC payload from a template.

The template is provided with --template. Its format is selected by the file
extension: '.yaml'/'.yml' and '.json' are parsed as YAML (JSON is a subset of
YAML), any other extension is parsed as TOML. It describes the ISD, the trust
policy, the validity period, and the certificates to include.

When updating an existing TRC, the predecessor TRC must be provided with
--predecessor. The command then reports which signatures the update requires.

The payload is written to standard output, or to the file given with
--out-file, encoded as PEM (default) or DER (--format). To inspect the DER
payload with openssl:

    openssl asn1parse -inform DER -i -in ISD1-B1-S1.pld.der

The payload still needs to be signed with 'trc sign' and assembled with
'trc combine'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			rep := app.NewReportForCmd(cmd)
			cfg, err := LoadPayload(flags.tmpl)
			if err != nil {
				return fmt.Errorf("failed to load template file: %w", err)
			}

			pred, err := loadPredecessor(rep, cmd.InOrStdin(),
				cfg.SerialVersion == cfg.BaseVersion, flags.pred)
			if err != nil {
				return err
			}
			prepareCfg(&cfg, pred)
			trc, err := CreatePayload(cfg, pred)
			if err != nil {
				return fmt.Errorf("failed to marshal TRC: %w", err)
			}
			if pred != nil {
				update, err := trc.ValidateUpdate(pred)
				if err != nil {
					return fmt.Errorf("validating update: %w", err)
				}
				printUpdate(rep, update)
			}
			raw, err := trc.Encode()
			if err != nil {
				return fmt.Errorf("encoding payload: %w", err)
			}
			return writeOutput(rep, flags.out, flags.format, "TRC PAYLOAD", raw)
		},
	}

	addOutFileFlag(&flags.out, cmd)
	cmd.Flags().StringVarP(&flags.tmpl, "template", "t", "", "Template file (required)")
	cmd.MarkFlagRequired("template")
	cmd.Flags().StringVarP(&flags.pred, "predecessor", "p", "", "Predecessor TRC")
	addFormatFlag(&flags.format, cmd)

	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		newPayloadDummy(joined),
	)

	return cmd
}

//go:embed testdata/admin/ISD1-B1-S1.pld.der
var dummyPayload []byte

func newPayloadDummy(_ command.Pather) *cobra.Command {
	var flags struct {
		format string
	}

	cmd := &cobra.Command{
		Use:   "dummy",
		Short: "Generate a dummy TRC payload",
		Long: `Generate a fixed, built-in dummy TRC payload.

The dummy payload is not a valid TRC, but it can be signed with 'trc sign' to
check that the required cryptographic material (keys and certificates) is
accessible and usable. This is especially useful when rehearsing a TRC signing
ceremony.

The payload is written to standard output, encoded as PEM (default) or DER
(--format).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return writeOutput(app.NewReportForCmd(cmd), "", flags.format,
				"TRC PAYLOAD", dummyPayload)
		},
	}
	addFormatFlag(&flags.format, cmd)
	return cmd
}

// CreatePayload creates the ASN.1 payload for the TRC from the given
// configuration.
func CreatePayload(cfg Payload, pred *cppki.TRC) (*cppki.TRC, error) {
	certs, err := cfg.Certificates(pred)
	if err != nil {
		return nil, err
	}

	v := cfg.Validity.Eval(time.Now())
	trc := &cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    cfg.ISD,
			Base:   cfg.BaseVersion,
			Serial: cfg.SerialVersion,
		},
		Validity: v,
		GracePeriod: func() time.Duration {
			if cfg.GracePeriod == nil {
				return 0
			}
			return cfg.GracePeriod.Duration
		}(),
		NoTrustReset:      cfg.NoTrustReset,
		Votes:             cfg.Votes,
		Quorum:            int(cfg.VotingQuorum),
		CoreASes:          cfg.CoreASes,
		AuthoritativeASes: cfg.AuthoritativeASes,
		Description:       cfg.Description,
		Certificates:      certs,
	}
	if err := trc.Validate(); err != nil {
		return nil, err
	}
	return trc, nil
}

func loadPredecessor(rep app.Report, stdin io.Reader, base bool, pred string) (*cppki.TRC, error) {
	if base && pred != "" {
		return nil, errors.New("predecessor specified for base TRC")
	}
	if base {
		rep.Errln("Generating payload for base TRC.")
		return nil, nil
	}
	if pred == "" {
		return nil, errors.New("missing predecessor file." +
			" Specify the predecessor TRC via --predecessor")
	}
	trc, err := DecodeFromFile(pred, stdin)
	if err != nil {
		return nil, fmt.Errorf("loading predecessor TRC %q: %w", pred, err)
	}
	rep.Errln("Generating payload for TRC update.")
	return &trc.TRC, nil
}

func prepareCfg(cfg *Payload, pred *cppki.TRC) {
	if pred == nil {
		sort.Slice(cfg.AuthoritativeASes, func(i, j int) bool {
			return cfg.AuthoritativeASes[i] < cfg.AuthoritativeASes[j]
		})
		sort.Slice(cfg.CoreASes, func(i, j int) bool {
			return cfg.CoreASes[i] < cfg.CoreASes[j]
		})
		return
	}
	// Keep this! TRCs generated with old version of the tool might not be
	// sorted.
	cfg.AuthoritativeASes = mimicOrder(cfg.AuthoritativeASes, pred.AuthoritativeASes)
	cfg.CoreASes = mimicOrder(cfg.CoreASes, pred.CoreASes)
	sort.Ints(cfg.Votes)
}

// mimicOrder mimics the order of the predecessor sequence. In a regular update,
// the sequence MUST not be changed, thus we attempt to mimic the order of the
// predecessor.
func mimicOrder(next, predecessor []addr.AS) []addr.AS {
	if len(next) != len(predecessor) {
		return next
	}
	m := map[addr.AS]struct{}{}
	for _, as := range predecessor {
		m[as] = struct{}{}
	}
	for _, as := range next {
		if _, ok := m[as]; !ok {
			return next
		}
	}
	return predecessor
}

func printUpdate(rep app.Report, update cppki.Update) {
	type desc struct {
		Type   string `yaml:"type"`
		CN     string `yaml:"common name"`
		Serial string `yaml:"serial number"`
	}
	var descs []desc
	for _, v := range []struct {
		Type  string
		Certs []*x509.Certificate
	}{
		{Type: "vote", Certs: update.Votes},
		{Type: "proof of possession", Certs: update.NewVoters},
		{Type: "acknowledgement", Certs: update.RootAcknowledgments},
	} {
		sort.Slice(v.Certs, func(i, j int) bool {
			return v.Certs[i].Subject.CommonName < v.Certs[j].Subject.CommonName
		})
		for _, cert := range v.Certs {
			descs = append(descs, desc{
				Type:   v.Type,
				CN:     cert.Subject.CommonName,
				Serial: fmt.Sprintf("% X", cert.SerialNumber.Bytes()),
			})
		}

	}
	out, err := yaml.Marshal(map[string][]desc{"required signatures": descs})
	if err != nil {
		return
	}
	rep.Errf("\n%s\n", string(out))
}
