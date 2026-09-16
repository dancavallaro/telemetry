package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dancavallaro/telemetry/pkg/espattest"
)

func writeEnrollment(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrollment.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoadEnrollmentDecodesSecrets(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"`+secret+`"}}`)

	devices, err := loadEnrollment(path)
	require.NoError(t, err)

	require.Len(t, devices, 1)
	assert.Equal(t, []byte("0123456789abcdef0123456789abcdef"), devices["a1b2c3d4e5f6"].Secret)
}

func TestLoadEnrollmentRejectsBadBase64(t *testing.T) {
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"not!base64"}}`)

	_, err := loadEnrollment(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "a1b2c3d4e5f6")
}

// A short secret means a provisioning mistake, and failing at startup is far
// easier to diagnose than every attestation silently failing later.
func TestLoadEnrollmentRejectsShortSecret(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("too-short"))
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"`+secret+`"}}`)

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

// Routing is the one seam unit tests on the verifier cannot cover, and a wrong
// path or method would only show up after a deploy.
func TestMuxRoutesAttestAndHealthz(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := writeEnrollment(t, `{"a1b2c3d4e5f6":{"secret":"`+secret+`"}}`)
	devices, err := loadEnrollment(path)
	require.NoError(t, err)

	srv := httptest.NewServer(newMux(&espattest.Verifier{
		Devices: devices,
		Skew:    60 * time.Second,
		Logf:    t.Logf,
	}))
	defer srv.Close()

	health, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer health.Body.Close()
	assert.Equal(t, http.StatusOK, health.StatusCode)

	e := espattest.Evidence{DeviceID: "a1b2c3d4e5f6", TS: time.Now().Unix(), Nonce: "deadbeefcafe0001"}
	e.MAC = espattest.Sign(e.DeviceID, e.TS, e.Nonce, devices["a1b2c3d4e5f6"].Secret)
	evidence, err := json.Marshal(e)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"payload": string(evidence)})
	require.NoError(t, err)

	resp, err := http.Post(srv.URL+"/attest", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Empty(t, got["error"])
	assert.Equal(t, "a1b2c3d4e5f6", got["device_id"])

	wrongMethod, err := http.Get(srv.URL + "/attest")
	require.NoError(t, err)
	defer wrongMethod.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, wrongMethod.StatusCode)
}
