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
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

type Info struct {
	Version           int          `yaml:"version" json:"version"`
	ID                ID           `yaml:"id" json:"id"`
	Validity          Validity     `yaml:"validity" json:"validity"`
	GracePeriod       string       `yaml:"graceperiod,omitempty" json:"graceperiod,omitempty"`
	GracePeriodEnd    time.Time    `yaml:"graceperiod_end,omitempty" json:"graceperiod_end,omitempty"`
	NoTrustReset      bool         `yaml:"no_trust_reset" json:"no_trust_reset"`
	Votes             []int        `yaml:"votes,omitempty" json:"votes,omitempty"`
	Quorum            int          `yaml:"voting_quorum" json:"voting_quorum"`
	CoreASes          []addr.AS    `yaml:"core_ases" json:"core_ases"`
	AuthoritativeASes []addr.AS    `yaml:"authoritative_ases" json:"authoritative_ases"`
	Description       string       `yaml:"description" json:"description"`
	Certificates      []CertDesc   `yaml:"certificates" json:"certificates"`
	Signatures        []SignerInfo `yaml:"signatures,omitempty" json:"signatures,omitempty"`
}

type ID struct {
	ISD    addr.ISD `yaml:"isd" json:"isd"`
	Base   uint64   `yaml:"base_number" json:"base_number"`
	Serial uint64   `yaml:"serial_number" json:"serial_number"`
}

type Validity struct {
	NotBefore time.Time `yaml:"not_before" json:"not_before"`
	NotAfter  time.Time `yaml:"not_after" json:"not_after"`
}

type CertDesc struct {
	Type         string   `yaml:"type,omitempty" json:"type,omitempty"`
	CommonName   string   `yaml:"common_name,omitempty" json:"common_name,omitempty"`
	IA           addr.IA  `yaml:"isd_as,omitempty" json:"isd_as,omitempty"`
	SerialNumber string   `yaml:"serial_number,omitempty" json:"serial_number,omitempty"`
	Validity     Validity `yaml:"validity,omitempty" json:"validity,omitempty"`
	Index        int      `yaml:"index" json:"index"`
	Error        string   `yaml:"error,omitempty" json:"error,omitempty"`
}

type SignerInfo struct {
	CommonName   string    `yaml:"common_name,omitempty" json:"common_name,omitempty"`
	IA           addr.IA   `yaml:"isd_as,omitempty" json:"isd_as,omitempty"`
	SerialNumber string    `yaml:"serial_number,omitempty" json:"serial_number,omitempty"`
	SigningTime  time.Time `yaml:"signing_time,omitempty" json:"signing_time,omitempty"`
	Purpose      string    `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Error        string    `yaml:"error,omitempty" json:"error,omitempty"`
}
