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
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"

	"github.com/scionproto-contrib/step-scion-plugin/private/app"
)

func NewCombineCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out     string
		payload string
		format  string
	}

	cmd := &cobra.Command{
		Use:   "combine <trc-file> [<trc-file>...]",
		Short: "Combine partially signed TRCs into a single signed TRC",
		Long: `Combine the signatures of multiple partially signed TRCs into a single TRC.

During a signing ceremony each voter signs the same TRC payload independently,
producing a set of partially signed TRCs. 'combine' merges the signatures from
all inputs into one signed TRC.

Each argument is a signed TRC file; pass "-" to read one from standard input.
The command checks that all inputs sign the exact same payload. If --payload is
provided, that payload is used as the reference and every input is compared
against it.

The combined TRC is written to standard output, or to the file given with
--out-file. Use --format to choose the encoding (pem or der).

No cryptographic verification of the signatures is performed. Use 'trc verify'
to validate the combined TRC.`,
		Example: fmt.Sprintf(`  %[1]s combine --payload ISD1-B1-S1.pld `+
			`ISD1-B1-S1.org1 ISD1-B1-S1.org2 > ISD1-B1-S1.trc`, pather.CommandPath()),
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runCombine(cmd, args, flags.payload, flags.out, flags.format)
		},
	}

	addOutFileFlag(&flags.out, cmd)
	cmd.Flags().StringVarP(&flags.payload, "payload", "p", "",
		"The TRC payload. If provided, it will be used as a reference payload to compare the "+
			"partially signed TRC payloads against. It can be either DER or PEM encoded.")
	addFormatFlag(&flags.format, cmd)

	return cmd
}

// runCombine combines the partially signed TRC files and writes the result to
// the output file, or to standard output if outFile is empty. pld is the
// optional reference payload file.
func runCombine(cmd *cobra.Command, files []string, pld, outFile, format string) error {
	trcs := make(map[string]cppki.SignedTRC)
	for _, name := range files {
		dec, err := DecodeFromFile(name, cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("error decoding part %q: %w", name, err)
		}
		trcs[name] = dec
	}
	if err := verifyPayload(pld, trcs); err != nil {
		return err
	}
	packed, err := CombineSignedPayloads(trcs)
	if err != nil {
		return err
	}
	return writeOutput(app.NewReportForCmd(cmd), outFile, format, "TRC", packed)
}

// CombineSignedPayloads combines the signed TRC payloads and checks that all payloads and
// signer infos are consistent.
func CombineSignedPayloads(trcs map[string]cppki.SignedTRC) ([]byte, error) {
	if err := verifyPayload("", trcs); err != nil {
		return nil, err
	}
	infos, err := combineSignerInfos(trcs)
	if err != nil {
		return nil, err
	}
	// Extract any payload. They are guaranteed to be the same
	var pld []byte
	for _, signed := range trcs {
		pld = signed.TRC.Raw
		break
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(pld)
	if err != nil {
		return nil, fmt.Errorf("error encoding payload: %w", err)
	}
	sd := protocol.SignedData{
		Version:          1,
		EncapContentInfo: eci,
		SignerInfos:      infos,
		DigestAlgorithms: combineDigestAlgorithms(infos),
	}
	// Write signed TRC.
	packed, err := sd.ContentInfoDER()
	if err != nil {
		return nil, fmt.Errorf("error packing combined TRC: %w", err)
	}
	return packed, nil
}

// combineSignerInfos combines all singer infos. It checks that non-unique
// signer infos are equal. The returned slice is sorted.
func combineSignerInfos(trcs map[string]cppki.SignedTRC) ([]protocol.SignerInfo, error) {
	type SignerOrigin struct {
		Info protocol.SignerInfo
		File string
	}
	var errs []error
	infos := make(map[string]SignerOrigin)
	for name, signed := range trcs {
		for _, si := range signed.SignerInfos {
			sid := string(si.SID.FullBytes)
			existing, ok := infos[sid]
			if !ok {
				infos[sid] = SignerOrigin{
					Info: si,
					File: name,
				}
				continue
			}
			if !reflect.DeepEqual(si, existing.Info) {
				errs = append(errs, fmt.Errorf(
					"different SignerInfo contents for same subject in files %v",
					[]string{name, existing.File}))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	var l []protocol.SignerInfo
	for _, info := range infos {
		l = append(l, info.Info)
	}
	// Keep sorting for consistent output for older go versions.
	// Starting from go1.15, the SignerInfos will be sorted when serializing.
	sort.Slice(l, func(i, j int) bool {
		return bytes.Compare(l[i].SID.FullBytes, l[j].SID.FullBytes) < 0
	})
	return l, nil
}

func combineDigestAlgorithms(infos []protocol.SignerInfo) []pkix.AlgorithmIdentifier {
	var algos []pkix.AlgorithmIdentifier
	for _, si := range infos {
		if !findDigestAlgorithm(si.DigestAlgorithm, algos) {
			algos = append(algos, si.DigestAlgorithm)
		}
	}
	sort.Slice(algos, func(i, j int) bool {
		return algos[i].Algorithm.String() < algos[j].Algorithm.String()
	})
	return algos
}

func findDigestAlgorithm(algo pkix.AlgorithmIdentifier, algos []pkix.AlgorithmIdentifier) bool {
	for _, existing := range algos {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return bytes.Equal(existing.Parameters.FullBytes, algo.Parameters.FullBytes)
		}
	}
	return false
}

func verifyPayload(pld string, trcs map[string]cppki.SignedTRC) error {
	var errs []error
	var rawPld []byte
	if pld != "" {
		var err error
		rawPld, err = os.ReadFile(pld)
		if err != nil {
			return fmt.Errorf("error loading payload: %w", err)
		}
		block, _ := pem.Decode(rawPld)
		if block != nil && block.Type == "TRC PAYLOAD" {
			rawPld = block.Bytes
		}
	}
	for name, signed := range trcs {
		if rawPld == nil {
			rawPld = signed.TRC.Raw
			continue
		}
		if !bytes.Equal(signed.TRC.Raw, rawPld) {
			errs = append(errs, fmt.Errorf("different payload contents in file %q", name))
		}
	}

	return errors.Join(errs...)
}
