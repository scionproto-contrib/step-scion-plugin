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

// Package cryptoutil provides helpers to load signing keys, either from disk or
// through the step-kms-plugin, and to derive public keys from PEM encoded
// material.
//
// The step-kms-plugin backed signer is a copy of
// https://github.com/smallstep/cli/blob/111bcb9cfbb101718f9c4a39f5ab439504b9c07f/internal/cryptoutil/cryptoutil.go
// with the irrelevant parts stripped out and small adjustments to make it fit
// our codebase.
package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/scionproto/scion/private/app"
)

// LoadPrivateKey loads a private key. If kms is empty, the key is read from the
// file at name (or standard input if name is "-"). Otherwise, the key is
// accessed through the step-kms-plugin.
//
// The key file may be PEM encoded in PKCS#8, PKCS#1 or SEC1 format, optionally
// encrypted. If the key is encrypted, the password is read from passwordFile.
// Encrypted keys without a passwordFile are rejected instead of prompting, so
// that the command remains usable non-interactively.
func LoadPrivateKey(kms, name, passwordFile string) (crypto.Signer, error) {
	if kms != "" {
		if passwordFile != "" {
			return nil, errors.New("password file is not supported with a KMS")
		}
		return NewKMSSigner(kms, name)
	}

	raw, err := app.ReadFileOrStdin(name)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	var opts []pemutil.Options
	if passwordFile != "" {
		opts = append(opts, pemutil.WithPasswordFile(passwordFile))
	}
	key, err := pemutil.Parse(raw, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	priv, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("file does not contain a private key: type %T", key)
	}
	return priv, nil
}

// IsX509Signer returns true if the given signer is supported by Go's
// crypto/x509 package to sign X509 certificates. This method returns true for
// ECDSA, RSA and Ed25519 keys.
func IsX509Signer(signer crypto.Signer) bool {
	if signer == nil {
		return false
	}
	switch signer.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

// LookKms looks up the step-kms-plugin binary in the PATH.
func LookKms() (string, error) {
	path, err := exec.LookPath("step-kms-plugin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "step-kms-plugin not found in PATH\n"+
			"Install it from https://github.com/smallstep/step-kms-plugin",
		)
		return "", err
	}
	return path, nil
}

type kmsSigner struct {
	crypto.PublicKey
	name     string
	kms, key string
}

// NewKMSSigner creates a signer that uses the step-kms-plugin to access the key
// identified by key in the given kms.
func NewKMSSigner(kms, key string) (crypto.Signer, error) {
	name, err := LookKms()
	if err != nil {
		return nil, err
	}

	args := []string{"key"}
	if kms != "" {
		args = append(args, "--kms", kms)
	}
	args = append(args, key)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}

	pub, err := LoadPublicKeyPEM(out)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{
		PublicKey: pub,
		name:      name,
		kms:       kms,
		key:       key,
	}, nil
}

// Public implements crypto.Signer and returns the public key.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign implements crypto.Signer using the step-kms-plugin.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	args := []string{"sign", "--format", "base64"}
	if s.kms != "" {
		args = append(args, "--kms", s.kms)
	}
	if _, ok := s.PublicKey.(*rsa.PublicKey); ok {
		if _, pss := opts.(*rsa.PSSOptions); pss {
			args = append(args, "--pss")
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			args = append(args, "--alg", "SHA256")
		case crypto.SHA384:
			args = append(args, "--alg", "SHA384")
		case crypto.SHA512:
			args = append(args, "--alg", "SHA512")
		default:
			return nil, fmt.Errorf("unsupported hash function %q", opts.HashFunc().String())
		}
	}
	args = append(args, s.key)

	//nolint:gosec // arguments controlled by step.
	cmd := exec.Command(s.name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(digest)
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}
	return base64.StdEncoding.DecodeString(string(out))
}

// exitError returns the error displayed on stderr after running the given
// command.
func exitError(cmd *exec.Cmd, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("command %q failed with:\n%s", cmd.String(), ee.Stderr)
	}
	return fmt.Errorf("command %q failed with: %w", cmd.String(), err)
}

// LoadPublicKeyPEM loads a public key from a PEM encoded private key, public
// key, or certificate.
func LoadPublicKeyPEM(raw []byte) (crypto.PublicKey, error) {
	v, err := pemutil.Parse(raw)
	if err != nil {
		return nil, err
	}
	if cert, ok := v.(*x509.Certificate); ok {
		return cert.PublicKey, nil
	}
	return keyutil.PublicKey(v)
}
