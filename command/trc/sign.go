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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/pemutil"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
	"github.com/scionproto-contrib/step-scion-plugin/private/cryptoutil"
)

func NewSignCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out          string
		outDir       string
		kms          string
		passwordFile string
	}

	cmd := &cobra.Command{
		Use:   "sign <payload-file> <crt-file> <key-file>",
		Short: "Sign a TRC payload",
		Example: fmt.Sprintf(
			`  %[1]s sign ISD1-B1-S1.pld.der sensitive-voting.crt sensitive-voting.key
  %[1]s sign ISD1-B1-S1.pld.der regular-voting.crt regular-voting.key --out ISD1-B1-S1.regular.trc
  %[1]s sign ISD1-B1-S1.pld.der cp-root.crt cp-root.key --password-file password.txt`,
			pather.CommandPath()),
		Long: `Sign a TRC payload with a signing certificate and its private key.

The signature type is derived from the certificate: a sensitive or regular
voting certificate produces a vote, and a root certificate produces a proof of
possession or root acknowledgement. Run the command once per voter to collect
all required signatures, then assemble them with 'trc combine'.

The private key is loaded from <key-file> (PKCS#8, PKCS#1 or SEC1, PEM
encoded). If the key is encrypted, provide the password in a file with
--password-file. To use a key held in a Cloud KMS or HSM instead, pass its URI
with --kms; the key is then accessed through the step-kms-plugin.

By default the signed TRC is written into --out-dir with the name

    ISD<isd>-B<base_version>-S<serial_number>.<signing-isd_as>-<signature-type>.trc

Use --out to write to a specific path instead.

If 'dummy' is given as the payload file, the built-in dummy payload is signed.
This is useful to check access to the cryptographic material when rehearsing a
signing ceremony.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunSign(app.NewReportForCmd(cmd), args[0], args[1], args[2],
				flags.kms, flags.passwordFile, flags.out, flags.outDir)
		},
	}

	cmd.Flags().StringVarP(&flags.out, "out", "o", "",
		"Output file path. Takes precedence over --out-dir.",
	)
	cmd.Flags().StringVar(&flags.outDir, "out-dir", ".",
		"Output directory for the auto-named TRC. Ignored when --out is set.",
	)
	cmd.Flags().StringVar(&flags.kms, "kms", "",
		"URI of the Cloud KMS or HSM that holds the signing key.",
	)
	cmd.Flags().StringVar(&flags.passwordFile, "password-file", "",
		"Path to a file with the password to decrypt the signing key.",
	)

	return cmd
}

func RunSign(rep app.Report, pld, certfile, keyName, kms, passwordFile, out, outDir string) error {
	dummy := pld == "dummy"

	// Read TRC payload
	rawPld, err := func() ([]byte, error) {
		if !dummy {
			return os.ReadFile(pld)
		}
		return dummyPayload, nil
	}()
	if err != nil {
		return fmt.Errorf("error loading payload: %w", err)
	}
	pldBlock, _ := pem.Decode(rawPld)
	if pldBlock != nil && pldBlock.Type == "TRC PAYLOAD" {
		rawPld = pldBlock.Bytes
	}
	// Load signing key
	priv, err := cryptoutil.LoadPrivateKey(kms, keyName, passwordFile)
	if err != nil {
		return err
	}
	// Load signing cert
	cert, err := pemutil.ReadCertificate(certfile)
	if err != nil {
		return fmt.Errorf("error loading signer: %w", err)
	}
	signed, err := SignPayload(rawPld, priv, cert)
	if err != nil {
		return fmt.Errorf("error signing TRC payload: %w", err)
	}
	// Verify the signed TRC payload as a sanity check
	signedTRC, err := cppki.DecodeSignedTRC(signed)
	if err != nil {
		return fmt.Errorf("error decoding signed TRC payload: %w", err)
	}
	if err := verifyBundle(signedTRC, []*x509.Certificate{cert}); err != nil {
		return fmt.Errorf("error verifying signed TRC payload: %w", err)
	}
	signed = pem.EncodeToMemory(&pem.Block{
		Type:  "TRC",
		Bytes: signed,
	})
	fname, err := outPath(out, outDir, &signedTRC.TRC, cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fname, signed, 0644); err != nil {
		return fmt.Errorf("error writing signed TRC payload: %w", err)
	}

	if !dummy {
		rep.Errlnf("Successfully signed TRC payload at %s", fname)
	} else {
		rep.Errln("Successfully signed dummy TRC payload")
	}
	return nil
}

func SignPayload(pld []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	eci, err := protocol.NewDataEncapsulatedContentInfo(pld)
	if err != nil {
		return nil, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		return nil, err
	}
	if err := sd.AddSignerInfo([]*x509.Certificate{cert}, signer); err != nil {
		return nil, err
	}
	// AddSignerInfo also adds the signing certificate to the CMS envelop, however, as it's already
	// included in the TRC payload or in the previous TRC in case of a vote, we remove it again.
	sd.Certificates = []asn1.RawValue{}

	return sd.ContentInfoDER()
}

func outPath(out, outDir string, trc *cppki.TRC, cert *x509.Certificate) (string, error) {
	if out != "" {
		return out, nil
	}
	ia, err := cppki.ExtractIA(cert.Subject)
	if err != nil {
		return "", fmt.Errorf("extracting ISD-AS from signing certificate: %w", err)
	}
	signType, err := signatureType(trc, cert)
	if err != nil {
		return "", fmt.Errorf("determining cert type: %w", err)
	}
	fname := fmt.Sprintf("ISD%d-B%d-S%d.%s-%s.trc", trc.ID.ISD, trc.ID.Base, trc.ID.Serial,
		addr.FormatIA(ia, addr.WithFileSeparator()), signType)
	return filepath.Join(outDir, fname), nil
}

func signatureType(trc *cppki.TRC, cert *x509.Certificate) (string, error) {
	certType, err := cppki.ValidateCert(cert)
	if err != nil {
		return "", err
	}
	inTRC := find(cert, trc.Certificates)
	switch certType {
	case cppki.Sensitive:
		if inTRC {
			return "sensitive", nil
		}
		return "sensitive-vote", nil
	case cppki.Regular:
		if inTRC {
			return "regular", nil
		}
		return "regular-vote", nil
	case cppki.Root:
		return "root-ack", nil
	}
	return "", errors.New("invalid signing cert type")
}

func find(cert *x509.Certificate, certs []*x509.Certificate) bool {
	for _, c := range certs {
		if bytes.Equal(c.Raw, cert.Raw) {
			return true
		}
	}
	return false
}
