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

// This file duplicates the TRC template configuration handling that previously
// lived in github.com/scionproto/scion/scion-pki/conf, so that this plugin does
// not depend on any package under scion-pki.

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.step.sm/crypto/pemutil"
	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/config"
)

// Payload holds the TRC payload input.
type Payload struct {
	ISD               addr.ISD        `toml:"isd" yaml:"isd" json:"isd"`
	Description       string          `toml:"description" yaml:"description" json:"description"`
	SerialVersion     scrypto.Version `toml:"serial_version" yaml:"serial_version" json:"serial_version"`
	BaseVersion       scrypto.Version `toml:"base_version" yaml:"base_version" json:"base_version"`
	VotingQuorum      uint8           `toml:"voting_quorum" yaml:"voting_quorum" json:"voting_quorum"`
	GracePeriod       *util.DurWrap   `toml:"grace_period" yaml:"grace_period" json:"grace_period"`
	NoTrustReset      bool            `toml:"no_trust_reset" yaml:"no_trust_reset" json:"no_trust_reset"`
	Validity          Validity        `toml:"validity" yaml:"validity" json:"validity"`
	CoreASes          []addr.AS       `toml:"core_ases" yaml:"core_ases" json:"core_ases"`
	AuthoritativeASes []addr.AS       `toml:"authoritative_ases" yaml:"authoritative_ases" json:"authoritative_ases"`
	CertificateFiles  []string        `toml:"cert_files" yaml:"cert_files" json:"cert_files"`
	Votes             []int           `toml:"votes" yaml:"votes" json:"votes"`

	relPath string
}

// LoadPayload loads the TRC payload input from the provided file. The format is
// selected by the file extension: '.yaml'/'.yml' and '.json' are decoded as
// YAML (JSON is a subset of YAML), any other extension is decoded as TOML.
// The contents are already validated.
func LoadPayload(file string) (Payload, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return Payload{}, fmt.Errorf("reading TRC config file %q: %w", file, err)
	}
	var cfg Payload
	switch strings.ToLower(filepath.Ext(file)) {
	case ".yaml", ".yml", ".json":
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return Payload{}, fmt.Errorf("unable to load TRC config from file %q: %w", file, err)
		}
	default:
		if err := config.Decode(raw, &cfg); err != nil {
			return Payload{}, fmt.Errorf("unable to load TRC config from file %q: %w", file, err)
		}
	}
	if err := cfg.Validity.Validate(); err != nil {
		return Payload{}, fmt.Errorf("validating 'validity' section: %w", err)
	}
	if cfg.GracePeriod == nil && cfg.SerialVersion != cfg.BaseVersion {
		return Payload{}, fmt.Errorf("grace_period must be set for non-base TRCs")
	}
	cfg.relPath = filepath.Dir(file)
	return cfg, nil
}

// Certificates returns the specified certificates.
func (cfg *Payload) Certificates(pred *cppki.TRC) ([]*x509.Certificate, error) {
	if len(cfg.CertificateFiles) == 0 {
		return nil, fmt.Errorf("no cert_files specified")
	}

	certs := make([]*x509.Certificate, 0, len(cfg.CertificateFiles))
	for _, certFile := range cfg.CertificateFiles {

		if raw, ok := strings.CutPrefix(certFile, "predecessor:"); ok {
			if pred == nil {
				return nil, fmt.Errorf("predecessor certificate requested on base TRC")
			}
			idx, err := strconv.Atoi(raw)
			if err != nil {
				return nil, fmt.Errorf("parsing predecessor index %q: %w", raw, err)
			}
			if idx < 0 || idx >= len(pred.Certificates) {
				return nil, fmt.Errorf("predecessor index out of bounds: %d", idx)
			}
			certs = append(certs, pred.Certificates[idx])
			continue
		}

		if !strings.HasPrefix(certFile, "/") {
			certFile = filepath.Join(cfg.relPath, certFile)
		}
		cert, err := pemutil.ReadCertificate(certFile)
		if err != nil {
			return nil, fmt.Errorf("reading certificate %q: %w", certFile, err)
		}
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			return nil, fmt.Errorf("validating certificate %q: %w", certFile, err)
		}
		if ct != cppki.Sensitive && ct != cppki.Regular && ct != cppki.Root {
			return nil, fmt.Errorf("invalid certificate type in %q", certFile)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Time is a TOML-friendly time that accepts both unix timestamps and
// RFC3339 strings.
type Time time.Time

func (t Time) Time() time.Time {
	return time.Time(t)
}

func (t *Time) UnmarshalText(b []byte) error {
	unix, err := strconv.ParseUint(string(b), 10, 32)
	if err == nil {
		if unix == 0 {
			*t = Time{}
			return nil
		}
		*t = Time(util.SecsToTime(uint32(unix)))
		return nil
	}

	parsed, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return fmt.Errorf("unable to parse time: %w", err)
	}
	*t = Time(parsed)
	return nil
}

// Validity defines a validity period.
type Validity struct {
	NotBefore Time         `toml:"not_before" yaml:"not_before" json:"not_before"`
	NotAfter  Time         `toml:"not_after" yaml:"not_after" json:"not_after"`
	Validity  util.DurWrap `toml:"validity" yaml:"validity" json:"validity"`
}

// Validate checks that the validity is set.
func (v *Validity) Validate() error {
	if (v.Validity.Duration == 0) == (v.NotAfter.Time().IsZero()) {
		return fmt.Errorf("exactly one of 'validity' or 'not_after' must be set")
	}
	return nil
}

// Eval returns the validity period. The not before parameter is only used if
// the struct's not before field value is zero.
func (v Validity) Eval(notBefore time.Time) cppki.Validity {
	if nb := time.Time(v.NotBefore); !nb.IsZero() {
		notBefore = nb
	}
	return cppki.Validity{
		NotBefore: notBefore,
		NotAfter: func() time.Time {
			if !v.NotAfter.Time().IsZero() {
				return v.NotAfter.Time()
			}
			return notBefore.Add(v.Validity.Duration)
		}(),
	}
}
