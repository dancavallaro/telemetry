package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeEnrollment(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrollment.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoadEnrollmentDecodesSecrets(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"`+secret+`","model":"nodemcu-32s"}}`)

	devices, err := loadEnrollment(path)
	require.NoError(t, err)

	require.Len(t, devices, 1)
	assert.Equal(t, []byte("0123456789abcdef0123456789abcdef"), devices["a1b2c3d4e5f6"].Secret)
	assert.Equal(t, "nodemcu-32s", devices["a1b2c3d4e5f6"].Model)
}

func TestLoadEnrollmentRejectsBadBase64(t *testing.T) {
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"not!base64","model":"x"}}`)

	_, err := loadEnrollment(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "a1b2c3d4e5f6")
}

// A short secret means a provisioning mistake, and failing at startup is far
// easier to diagnose than every attestation silently failing later.
func TestLoadEnrollmentRejectsShortSecret(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("too-short"))
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"`+secret+`","model":"x"}}`)

	_, err := loadEnrollment(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestLoadEnrollmentRejectsMalformedJSON(t *testing.T) {
	path := writeEnrollment(t, `{`)

	_, err := loadEnrollment(path)

	require.Error(t, err)
}

func TestLoadEnrollmentRejectsEmptyMap(t *testing.T) {
	path := writeEnrollment(t, `{}`)

	_, err := loadEnrollment(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no devices")
}

func TestLoadEnrollmentRejectsMissingFile(t *testing.T) {
	_, err := loadEnrollment(filepath.Join(t.TempDir(), "absent.json"))

	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "absent.json"), "error should name the path: %v", err)
}
