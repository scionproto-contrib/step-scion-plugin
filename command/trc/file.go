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

// This file duplicates the file helpers that previously lived in
// github.com/scionproto/scion/scion-pki/file, so that this plugin does not
// depend on any package under scion-pki.

import (
	"errors"
	"fmt"
	"os"
)

// checkDirExists checks whether the provided directory exists.
func checkDirExists(dir string) error {
	stat, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("directory does not exist")
	}
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

// writeFile writes the supplied data to the file. If the file already exists,
// it is only overwritten when force is set.
func writeFile(filename string, data []byte, perm os.FileMode, force bool) error {
	info, err := os.Stat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(filename, data, perm)
	}
	if err != nil {
		return fmt.Errorf("reading stat information: %w", err)
	}
	if info.IsDir() {
		return errors.New("file is a directory")
	}
	if !force {
		return os.ErrExist
	}
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("removing existing file: %w", err)
	}
	return os.WriteFile(filename, data, perm)
}
