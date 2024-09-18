// Copyright 2024 Anapaya Systems
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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
)

const (
	PurposeVote     = "vote"
	PurposeNewVoter = "new voter"
	PurposeRootAck  = "root acknowledgement"
)

func NewInspectCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		format      string
		strict      bool
		predecessor string
	}

	cmd := &cobra.Command{
		Use:     "inspect <trc-file> ",
		Aliases: []string{"human", "print", "show"},
		Short:   "print TRC details in a human readable format",
		Example: fmt.Sprintf(`  %[1]s inspect ISD1-B1-S1.pld.der
  %[1]s inspect ISD1-B1-S1.trc`, pather.CommandPath()),
		Long: `prints the details of a TRC or partial TRC in a human- or machine-readable fromat.

Beware: TRCs are never verified. Always verify a TRC before relying on the output
of this command.

The input file can either be a TRC payload, a partial TRC with some signatures,
or a fully signed TRC. To read from standard input, specify "-" as the file name.

By default, this command attempts to handle decoding errors gracefully. To
return an error if parts of a TRC fail to decode, enable the strict mode.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoder, err := getEncoder(cmd.OutOrStdout(), flags.format)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			raw, err := func() ([]byte, error) {
				if args[0] == "-" {
					return io.ReadAll(cmd.InOrStdin())
				}
				return os.ReadFile(args[0])
			}()
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			trc, err := decodeTRCorPayload(raw)
			if err != nil {
				return fmt.Errorf("decoding input: %w", err)
			}

			var predecessor decoded
			if flags.predecessor != "" {
				predRaw, err := os.ReadFile(flags.predecessor)
				if err != nil {
					return err
				}
				predecessor, err = decodeTRCorPayload(predRaw)
				if err != nil {
					return err
				}
			}
			h, err := newTRCInfo(trc, predecessor, flags.strict)
			if err != nil {
				return err
			}
			return encoder.Encode(h)
		},
	}
	cmd.Flags().StringVar(&flags.format, "format", "yaml", "Output format (yaml|json)")
	cmd.Flags().BoolVar(&flags.strict, "strict", false, "Enable strict decoding mode")
	cmd.Flags().StringVar(&flags.predecessor, "predecessor", "",
		"Predecessor TRC (required to display signature purpose)")
	return cmd
}

func getEncoder(w io.Writer, format string) (interface{ Encode(v interface{}) error }, error) {
	switch format {
	case "yaml", "yml":
		return yaml.NewEncoder(w), nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		return enc, nil
	default:
		return nil, fmt.Errorf("format not supported: %s", format)
	}
}

type decoded struct {
	TRC    *cppki.TRC
	Signed *cppki.SignedTRC
}

func decodeTRCorPayload(raw []byte) (decoded, error) {
	block, rest := pem.Decode(raw)

	switch {
	case block == nil:
		// skip, potentially a raw TRC
	case len(bytes.TrimSpace(rest)) > 0:
		return decoded{}, fmt.Errorf("contains more than one PEM encoded block")
	case block.Type == "TRC" || block.Type == "TRC PAYLOAD":
		raw = block.Bytes
	default:
		return decoded{}, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if t, err := cppki.DecodeTRC(raw); err == nil {
		return decoded{TRC: &t}, nil
	} else if s, err := cppki.DecodeSignedTRC(raw); err == nil {
		return decoded{TRC: &s.TRC, Signed: &s}, nil
	}
	return decoded{}, fmt.Errorf("neither TRC nor signed TRC")
}

func newTRCInfo(trc decoded, pred decoded, strict bool) (Info, error) {
	var errs []error
	info := Info{
		Version: trc.TRC.Version,
		ID: ID{
			ISD:    trc.TRC.ID.ISD,
			Base:   uint64(trc.TRC.ID.Base),
			Serial: uint64(trc.TRC.ID.Serial),
		},
		Validity:          Validity(trc.TRC.Validity),
		NoTrustReset:      trc.TRC.NoTrustReset,
		Votes:             trc.TRC.Votes,
		Quorum:            trc.TRC.Quorum,
		CoreASes:          trc.TRC.CoreASes,
		AuthoritativeASes: trc.TRC.AuthoritativeASes,
		Description:       trc.TRC.Description,
		GracePeriod: func() string {
			if trc.TRC.ID.IsBase() {
				return ""
			}
			return trc.TRC.GracePeriod.String()
		}(),
		GracePeriodEnd: func() time.Time {
			if trc.TRC.ID.IsBase() {
				return time.Time{}
			}
			return trc.TRC.Validity.NotBefore.Add(trc.TRC.GracePeriod).UTC()
		}(),
		Certificates: func() []CertDesc {
			var certs []CertDesc
			for i, cert := range trc.TRC.Certificates {
				t, err := cppki.ValidateCert(trc.TRC.Certificates[0])
				if err != nil {
					certs = append(certs, CertDesc{Error: err.Error()})
					errs = append(errs, fmt.Errorf("classifying certificate %d: %w", i, err))
					continue
				}
				certs = append(certs, CertDesc{
					CommonName:   cert.Subject.CommonName,
					IA:           extractIA(cert.Subject),
					SerialNumber: fmt.Sprintf("% X", cert.SerialNumber.Bytes()),
					Type:         t.String(),
					Index:        i,
					Validity: Validity{
						NotBefore: cert.NotBefore,
						NotAfter:  cert.NotAfter,
					},
				})
			}
			return certs
		}(),
		Signatures: func() []SignerInfo {
			if trc.Signed == nil {
				return nil
			}
			predCerts := func() []*x509.Certificate {
				if pred.TRC == nil {
					return nil
				}
				return pred.TRC.Certificates
			}()
			var signers []SignerInfo
			for i, info := range trc.Signed.SignerInfos {
				d, err := newSignerInfo(info, predCerts)
				if err != nil {
					signers = append(signers, SignerInfo{Error: err.Error()})
					errs = append(errs, fmt.Errorf("decoding signer info %d: %w", i, err))
					continue
				}
				signers = append(signers, d)
			}
			return signers
		}(),
	}
	if err := errors.Join(errs...); err != nil && strict {
		return Info{}, err
	}
	return info, nil
}

func newSignerInfo(info protocol.SignerInfo, certs []*x509.Certificate) (SignerInfo, error) {
	if info.SID.Class != asn1.ClassUniversal || info.SID.Tag != asn1.TagSequence {
		return SignerInfo{}, errors.New("unsupported signer info type")
	}
	var isn protocol.IssuerAndSerialNumber
	if rest, err := asn1.Unmarshal(info.SID.FullBytes, &isn); err != nil {
		return SignerInfo{}, err
	} else if len(rest) > 0 {
		return SignerInfo{}, errors.New("trailing data")
	}
	var issuer pkix.RDNSequence
	if rest, err := asn1.Unmarshal(isn.Issuer.FullBytes, &issuer); err != nil {
		return SignerInfo{}, err
	} else if len(rest) != 0 {
		return SignerInfo{}, errors.New("trailing data")
	}
	signingTime, err := info.GetSigningTimeAttribute()
	if err != nil {
		return SignerInfo{}, err
	}

	var name pkix.Name
	name.FillFromRDNSequence(&issuer)
	return SignerInfo{
		CommonName:   name.CommonName,
		IA:           extractIA(name),
		SerialNumber: fmt.Sprintf("% X", isn.SerialNumber.Bytes()),
		SigningTime:  signingTime,
		Purpose:      getPurpose(info, certs),
	}, nil
}

func extractIA(name pkix.Name) addr.IA {
	ia, err := cppki.ExtractIA(name)
	if err != nil {
		return 0
	}
	return ia
}

func getPurpose(info protocol.SignerInfo, certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	cert, err := info.FindCertificate(certs)
	if err == protocol.ErrNoCertificate {
		return PurposeNewVoter
	} else if err != nil {
		return ""
	}
	certType, err := cppki.ValidateCert(cert)
	if err != nil {
		return ""
	}
	switch certType {
	case cppki.Sensitive, cppki.Regular:
		return PurposeVote
	case cppki.Root:
		return PurposeRootAck
	}
	return ""
}
