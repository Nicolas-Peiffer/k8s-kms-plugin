// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAlgorithmFamily_Set_Valid verifies that every documented slug is accepted.
func TestAlgorithmFamily_Set_Valid(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		a := AlgorithmFamilyAESGCM // start from a known state
		assert.NoErrorf(t, a.Set(v), "Set(%q) should succeed", v)
		assert.Equal(t, AlgorithmFamily(v), a)
	}
}

// TestAlgorithmFamily_Set_Invalid verifies that jose constants, size-qualified names,
// and empty strings are all rejected.
func TestAlgorithmFamily_Set_Invalid(t *testing.T) {
	invalid := []string{
		"",            // empty
		"aes",         // incomplete
		"aes-256-gcm", // size-qualified — user should not need to know the size
		"A256GCM",     // jose constant
		"RSA-OAEP",    // jose constant (wrong case)
		"MLKEM768",    // jose constant
		"unknown",
	}
	for _, v := range invalid {
		a := AlgorithmFamilyAESGCM
		assert.Errorf(t, a.Set(v), "Set(%q) should fail", v)
	}
}

// TestAlgorithmFamily_Set_DoesNotMutateOnError verifies that a failed Set() leaves
// the receiver unchanged.
func TestAlgorithmFamily_Set_DoesNotMutateOnError(t *testing.T) {
	a := AlgorithmFamilyRSAOAEP
	_ = a.Set("invalid")
	assert.Equal(t, AlgorithmFamilyRSAOAEP, a)
}

func TestAlgorithmFamily_String(t *testing.T) {
	cases := []struct {
		a    AlgorithmFamily
		want string
	}{
		{AlgorithmFamilyAESGCM, "aes-gcm"},
		{AlgorithmFamilyAESCBC, "aes-cbc"},
		{AlgorithmFamilyRSAOAEP, "rsa-oaep"},
		{AlgorithmFamilyMLKEM, "ml-kem"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.a.String())
	}
}

func TestAlgorithmFamily_Type(t *testing.T) {
	a := AlgorithmFamilyAESGCM
	assert.Equal(t, "algorithmFamily", a.Type())
}

// TestValidateAlgorithmFamily covers all valid slugs and a representative set of
// invalid inputs.
func TestValidateAlgorithmFamily(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		assert.NoErrorf(t, validateAlgorithmFamily(v), "validateAlgorithmFamily(%q) should succeed", v)
	}

	invalid := []string{
		"",
		"aes-256-gcm",
		"A256GCM",
		"RSA-OAEP",
		"MLKEM768",
		"aes gcm", // space instead of dash
	}
	for _, v := range invalid {
		err := validateAlgorithmFamily(v)
		assert.Errorf(t, err, "validateAlgorithmFamily(%q) should fail", v)
		assert.Contains(t, err.Error(), "must be one of")
	}
}

// TestSanitizeServeFlags_Valid confirms that a valid AlgorithmFamily passes
// without error.
func TestSanitizeServeFlags_Valid(t *testing.T) {
	for _, v := range []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"} {
		// SocketPath is set because the flag always carries a default in real use, and
		// sanitizeServeFlags rejects an empty one.
		f := &ServeFlags{AlgorithmFamily: v, SocketPath: "/run/k8s-kms-plugin.sock"}
		assert.NoErrorf(t, sanitizeServeFlags(f), "sanitize should accept %q", v)
	}
}

// TestSanitizeServeFlags_Invalid verifies that an unsupported value (e.g. from
// a config file) is rejected with a flag-prefixed error message.
func TestSanitizeServeFlags_Invalid(t *testing.T) {
	f := &ServeFlags{AlgorithmFamily: "aes-256-gcm"}
	err := sanitizeServeFlags(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
	assert.Contains(t, err.Error(), "must be one of")
}

// TestSanitizeServeFlags_Empty verifies that an empty string (e.g. missing
// config key) is rejected.
func TestSanitizeServeFlags_Empty(t *testing.T) {
	f := &ServeFlags{AlgorithmFamily: ""}
	err := sanitizeServeFlags(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
}

// TestSanitizeServeFlags_LabelLimits verifies that CKA_LABEL strings over the
// PKCS#11 255-byte maximum are rejected with flag-prefixed error messages.
func TestSanitizeServeFlags_LabelLimits(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelBytes)
	overLimit := strings.Repeat("a", maxCkaLabelBytes+1)
	const validSocket = "/run/k8s-kms-plugin.sock"

	cases := []struct {
		name    string
		flags   ServeFlags
		wantErr string
	}{
		{
			"all labels at limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: validSocket, P11Label: atLimit, DekKeyLabel: atLimit, HmacKeyLabel: atLimit},
			"",
		},
		{
			"p11-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: validSocket, P11Label: overLimit},
			"--p11-label",
		},
		{
			"p11-key-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: validSocket, DekKeyLabel: overLimit},
			"--p11-key-label",
		},
		{
			"p11-hmac-label over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: validSocket, HmacKeyLabel: overLimit},
			"--p11-hmac-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeServeFlags(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestSanitizeServeFlags_SocketPathLimit verifies that Unix socket paths over
// 107 bytes are rejected.
func TestSanitizeServeFlags_SocketPathLimit(t *testing.T) {
	atLimit := strings.Repeat("a", maxUnixSocketPathLen)
	overLimit := strings.Repeat("a", maxUnixSocketPathLen+1)

	cases := []struct {
		name    string
		flags   ServeFlags
		wantErr string
	}{
		{
			"at limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: atLimit},
			"",
		},
		{
			"over limit",
			ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: overLimit},
			"--socket",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeServeFlags(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestSanitizeServeFlags_RejectsAbstractSocket pins the rejection of abstract unix sockets.
//
// An abstract socket (a name starting with "@" or NUL) lives in the network namespace, not the
// filesystem, so it has no owner and no mode: nothing can stop any process in the namespace
// connecting and asking the plugin to unwrap DEKs. listenOnUnixSocket's permission handling is
// meaningless for one, so the only defence is to refuse the flag value outright.
func TestSanitizeServeFlags_RejectsAbstractSocket(t *testing.T) {
	cases := []struct {
		name    string
		socket  string
		wantErr string
	}{
		{"at sign prefix", "@k8s-kms-plugin", "abstract socket"},
		{"nul prefix", "\x00k8s-kms-plugin", "abstract socket"},
		{"empty", "", "path is empty"},
		{"filesystem path is accepted", "/run/k8s-kms-plugin.sock", ""},
		{"at sign elsewhere is accepted", "/run/user@1000/plugin.sock", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags := ServeFlags{AlgorithmFamily: "aes-gcm", SocketPath: tc.socket}
			err := sanitizeServeFlags(&flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestListenOnUnixSocket_CreatesSocketWithIntendedMode verifies that the socket reaches the
// filesystem already carrying socketPerm.
//
// The mode has to be right at creation rather than set afterwards: a chmod resolves the path a
// second time and can be redirected through a symlink. Asserting the mode on the created socket
// is what catches a regression back to the chmod form, since both produce a working socket.
func TestListenOnUnixSocket_CreatesSocketWithIntendedMode(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "plugin.sock")

	l, err := listenOnUnixSocket(sock)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	fi, err := os.Lstat(sock)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(socketPerm), fi.Mode().Perm(),
		"socket must be created with socketPerm, not chmod-ed afterwards")
	assert.NotZero(t, fi.Mode()&os.ModeSocket, "path must be a socket")
}

// TestListenOnUnixSocket_ReplacesStaleSocket covers the restart case: a socket left by a
// previous run is removed rather than causing "address already in use".
func TestListenOnUnixSocket_ReplacesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "plugin.sock")

	first, err := listenOnUnixSocket(sock)
	require.NoError(t, err)
	require.NoError(t, first.Close())

	second, err := listenOnUnixSocket(sock)
	require.NoError(t, err, "a socket left behind by a previous run must be replaced")
	defer func() { _ = second.Close() }()
}

// TestListenOnUnixSocket_RefusesToRemoveNonSocket pins the guard on the unlink.
//
// The path comes from a flag, an environment variable or a config file, so pointing it at a
// regular file is an ordinary mistake. Unlinking whatever happens to be there would make that
// mistake destructive, so anything that is not a socket is left alone and reported.
func TestListenOnUnixSocket_RefusesToRemoveNonSocket(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "important.conf")
	require.NoError(t, os.WriteFile(victim, []byte("do not delete"), 0o600))

	l, err := listenOnUnixSocket(victim)
	require.Error(t, err)
	if l != nil {
		_ = l.Close()
	}
	assert.Contains(t, err.Error(), "not a socket")

	content, readErr := os.ReadFile(victim)
	require.NoError(t, readErr, "the file must still exist")
	assert.Equal(t, "do not delete", string(content), "the file must be untouched")
}
