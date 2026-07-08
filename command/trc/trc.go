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
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/private/app/command"
)

func NewCmd(pather command.Pather) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "trc",
		Aliases: []string{"trcs"},
		Short:   "Create, inspect, and verify TRCs for the SCION control plane PKI",
		Long: `Manage Trust Root Configurations (TRCs) for the SCION control plane PKI.

A TRC is the trust anchor of an ISD. It bundles the ISD's voting and root
certificates together with the trust policy, and is signed by the voters.

The subcommands cover the full TRC lifecycle:

  - payload:      generate a TRC payload from a template
  - sign:         sign a TRC payload with a voting or root key
  - combine:      merge the individual signatures into one signed TRC
  - verify:       verify a TRC or a TRC update chain against a trust anchor
  - inspect:      print the contents of a TRC in a human-readable format
  - format:       convert a TRC or payload between PEM and DER
  - extract:      extract the payload or the bundled certificates from a TRC

Unless noted otherwise, commands read from a file or from standard input when
the file name is "-", and write to standard output unless an output file is
given.`,
	}
	joined := command.Join(pather, cmd)
	cmd.AddCommand(
		NewCombineCmd(joined),
		NewInspectCmd(joined),
		NewFormatCmd(joined),
		NewExtractCmd(joined),
		NewPayloadCmd(joined),
		NewVerifyCmd(joined),
		NewSignCmd(joined),
	)
	return cmd
}
