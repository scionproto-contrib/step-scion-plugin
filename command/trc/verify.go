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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/pemutil"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cms/oid"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

func NewVerifyCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		anchor string
		isd    uint16
	}

	cmd := &cobra.Command{
		Use:   "verify <trc-file> [<trc-file>...]",
		Short: "Verify a TRC or a TRC update chain",
		Example: fmt.Sprintf(`  %[1]s verify --anchor bundle.pem ISD1-B1-S1.trc
  %[1]s verify --anchor ISD1-B1-S1.trc ISD1-B1-S2.trc ISD1-B1-S3.trc`, pather.CommandPath()),
		Long: `Verify a TRC, or a chain of TRC updates, against a trusted anchor.

The TRCs are the arguments; pass "-" to read one from standard input. Multiple
TRCs are ordered by serial number and verified as an update chain, where each
TRC is verified against its predecessor. The chain must be contiguous and all
TRCs must belong to the same ISD and base version.

The trust anchor is given with --anchor. It is either a trusted TRC, or a PEM
bundle of trusted certificates. A chain that starts with a base TRC can be
anchored by either; a chain that starts with a non-base TRC must be anchored by
a TRC.

Use --isd to assert that the TRCs belong to the expected ISD; verification
fails if they do not.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return RunVerify(app.NewReportForCmd(cmd), cmd.InOrStdin(),
				args, flags.anchor, addr.ISD(flags.isd))
		},
	}

	cmd.Flags().StringVarP(&flags.anchor, "anchor", "a", "",
		"Trusted anchor, either a TRC or a PEM certificate bundle (required)",
	)
	cmd.Flags().Uint16Var(&flags.isd, "isd", 0,
		"Expected ISD identifier to match against the TRCs",
	)
	cmd.MarkFlagRequired("anchor")
	return cmd
}

// RunVerify runs verification of the TRC files from the given anchor.
func RunVerify(rep app.Report, stdin io.Reader, files []string, anchor string, isd addr.ISD) error {
	var trcs []cppki.SignedTRC
	for _, name := range files {
		dec, err := DecodeFromFile(name, stdin)
		if err != nil {
			return fmt.Errorf("error decoding TRC %q: %w", name, err)
		}
		trcs = append(trcs, dec)
	}
	if len(trcs) == 0 {
		return errors.New("TRC verify requires at least one TRC to verify")
	}
	someISD, someBase := trcs[0].TRC.ID.ISD, trcs[0].TRC.ID.Base
	for _, dec := range trcs {
		if someISD != dec.TRC.ID.ISD {
			return fmt.Errorf("multiple ISDs: %v", []addr.ISD{someISD, dec.TRC.ID.ISD})
		}
		if someBase != dec.TRC.ID.Base {
			return fmt.Errorf("multiple base versions: %v",
				[]scrypto.Version{someBase, dec.TRC.ID.Base})
		}
	}
	sort.Slice(trcs, func(i, j int) bool {
		return trcs[i].TRC.ID.Serial < trcs[j].TRC.ID.Serial
	})
	if anchorISD := trcs[0].TRC.ID.ISD; isd != 0 && anchorISD != isd {
		return fmt.Errorf(
			"TRC anchor ISD does not match the requested ISD ID: expected %d, actual %d",
			isd, anchorISD)
	}
	serials := []scrypto.Version{trcs[0].TRC.ID.Serial}
	for i := 1; i < len(trcs); i++ {
		serials = append(serials, trcs[i].TRC.ID.Serial)
		if serials[i] != serials[i-1]+1 {
			return fmt.Errorf("gap in TRC update chain: serial numbers %v", serials)
		}
	}
	if err := verifyInitial(trcs[0], anchor, stdin); err != nil {
		return fmt.Errorf("verifying first TRC in update chain (id %v): %w", trcs[0].TRC.ID, err)
	}
	rep.Errln("Verified TRC successfully:", trcs[0].TRC.ID)
	for i := 1; i < len(trcs); i++ {
		if err := trcs[i].Verify(&trcs[i-1].TRC); err != nil {
			return fmt.Errorf("verifying TRC update (id %v): %w", trcs[i].TRC.ID, err)
		}
		rep.Errln("Verified TRC successfully:", trcs[i].TRC.ID)
	}
	return nil
}

func verifyInitial(trc cppki.SignedTRC, anchor string, stdin io.Reader) error {
	if !trc.TRC.ID.IsBase() {
		a, err := DecodeFromFile(anchor, stdin)
		if err != nil {
			return fmt.Errorf("loading TRC anchor %q: %w", anchor, err)
		}
		return trc.Verify(&a.TRC)
	}

	if err := trc.Verify(nil); err != nil {
		return fmt.Errorf("verifying proof of possession: %w", err)
	}
	certs, err := loadAnchorCerts(anchor, stdin)
	if err != nil {
		return fmt.Errorf("loading anchor %q: %w", anchor, err)
	}
	if err := verifyBundle(trc, certs); err != nil {
		return fmt.Errorf("checking verifiable with bundled certificates: %w", err)
	}
	return nil
}

func loadAnchorCerts(file string, stdin io.Reader) ([]*x509.Certificate, error) {
	if info, err := os.Stat(file); err != nil {
		return nil, err
	} else if info.IsDir() {
		return nil, errors.New("anchor is a directory")
	}
	dec, trcErr := DecodeFromFile(file, stdin)
	if trcErr == nil {
		return dec.TRC.Certificates, nil
	}
	certs, certErr := pemutil.ReadCertificateBundle(file)
	if certErr == nil {
		return certs, nil
	}
	return nil, fmt.Errorf("anchor contents not supported: %w",
		errors.Join(trcErr, certErr))
}

func verifyBundle(signed cppki.SignedTRC, certs []*x509.Certificate) error {
	if len(signed.SignerInfos) == 0 {
		return errors.New("no signatures found")
	}
	for i, si := range signed.SignerInfos {
		if err := verifySignerInfo(si, signed.TRC.Raw, certs); err != nil {
			return fmt.Errorf("verifying signer info %d: %w", i, err)
		}
	}
	return nil
}

func verifySignerInfo(si protocol.SignerInfo, pld []byte, certs []*x509.Certificate) error {
	if si.SignedAttrs == nil {
		return errors.New("SignerInfo without signed attributes")
	}
	siContentType, err := si.GetContentTypeAttribute()
	if err != nil {
		return fmt.Errorf("error getting ContentType: %w", err)
	}
	if !siContentType.Equal(oid.ContentTypeData) {
		return fmt.Errorf("SignerInfo with invalid ContentType: %v", siContentType)
	}
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	attrDigest, err := si.GetMessageDigestAttribute()
	if err != nil {
		return fmt.Errorf("SignerInfo with invalid message digest: %w", err)
	}
	actualDigest := hash.New()
	actualDigest.Write(pld)
	if !bytes.Equal(attrDigest, actualDigest.Sum(nil)) {
		return errors.New("invalid SignerInfo message digest")
	}
	input, err := si.SignedAttrs.MarshaledForVerifying()
	if err != nil {
		return fmt.Errorf("error marshalling signature input: %w", err)
	}
	// FIXME(roosd): this also finds certificates based on subject key id.
	cert, err := si.FindCertificate(certs)
	if err != nil {
		return err
	}
	if err := cert.CheckSignature(si.X509SignatureAlgorithm(), input, si.Signature); err != nil {
		return err
	}
	// FIXME(roosd): Check timestamps
	return nil
}
