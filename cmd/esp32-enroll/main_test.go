package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dancavallaro/telemetry/pkg/espattest"
)

func TestGenerateSecretProducesDistinct32ByteSecrets(t *testing.T) {
	a, err := generateSecret()
	require.NoError(t, err)
	b, err := generateSecret()
	require.NoError(t, err)

	assert.NotEqual(t, a, b)

	raw, err := base64.StdEncoding.DecodeString(a)
	require.NoError(t, err)
	assert.Len(t, raw, 32)
}

// The enrollment entry is consumed by esp32-attestor's loadEnrollment, so its
// shape has to stay in step with that parser.
func TestEnrollmentJSONMatchesTheWebhookFormat(t *testing.T) {
	secret, err := generateSecret()
	require.NoError(t, err)

	body, err := enrollmentJSON("a1b2c3d4e5f6", "nodemcu-32s", secret)
	require.NoError(t, err)

	var parsed map[string]struct {
		Secret string `json:"secret"`
		Model  string `json:"model"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))

	require.Contains(t, parsed, "a1b2c3d4e5f6")
	assert.Equal(t, "nodemcu-32s", parsed["a1b2c3d4e5f6"].Model)
	raw, err := base64.StdEncoding.DecodeString(parsed["a1b2c3d4e5f6"].Secret)
	require.NoError(t, err)
	assert.Len(t, raw, 32)
}

func TestNVSCSVCarriesTheSecretAsBase64Data(t *testing.T) {
	csv := nvsCSV("c2VjcmV0")

	lines := strings.Split(strings.TrimSpace(csv), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, "key,type,encoding,value", lines[0])
	assert.Equal(t, "spiffe,namespace,,", lines[1])
	assert.Equal(t, "device_secret,data,base64,c2VjcmV0", lines[2])
}

// This is the contract the firmware reimplements in C, so it must verify with
// the same secret the webhook holds.
func TestBuildEvidenceVerifiesWithTheDeviceSecret(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	raw, err := buildEvidence("a1b2c3d4e5f6", secret, 1789200000, "deadbeefcafe0001")
	require.NoError(t, err)

	var e espattest.Evidence
	require.NoError(t, json.Unmarshal(raw, &e))

	assert.Equal(t, "a1b2c3d4e5f6", e.DeviceID)
	assert.Equal(t, int64(1789200000), e.TS)
	assert.Equal(t, "deadbeefcafe0001", e.Nonce)
	assert.True(t, e.Verify(secret), "webhook would reject this evidence")
}

func TestBuildEvidenceIsASCIIOnly(t *testing.T) {
	raw, err := buildEvidence("a1b2c3d4e5f6", []byte("0123456789abcdef0123456789abcdef"), 1789200000, "deadbeefcafe0001")
	require.NoError(t, err)

	for i, b := range raw {
		require.Less(t, b, byte(0x80), "byte %d of %q is not 7-bit ASCII", i, raw)
	}
}

func TestNormalizeEndpointAddsHTTPS(t *testing.T) {
	assert.Equal(t, "https://defakto.o.cavnet.cloud", normalizeEndpoint("defakto.o.cavnet.cloud"))
	assert.Equal(t, "https://defakto.o.cavnet.cloud", normalizeEndpoint("https://defakto.o.cavnet.cloud"))
	assert.Equal(t, "https://defakto.o.cavnet.cloud", normalizeEndpoint("https://defakto.o.cavnet.cloud/"))
}
