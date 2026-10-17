package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/proto"

	"github.com/dancavallaro/telemetry/pkg/espattest"
	pb "github.com/dancavallaro/telemetry/pkg/spirlweb/serverlessapi"
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

	body, err := enrollmentJSON("a1b2c3d4e5f6", secret)
	require.NoError(t, err)

	var parsed map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))

	require.Contains(t, parsed, "a1b2c3d4e5f6")
	assert.Equal(t, []string{"secret"}, keysOf(parsed["a1b2c3d4e5f6"]))
	raw, err := base64.StdEncoding.DecodeString(parsed["a1b2c3d4e5f6"]["secret"])
	require.NoError(t, err)
	assert.Len(t, raw, 32)
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

func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The firmware takes its ID from DEVICE_NAME, so NVS carries only the secret.
func TestNVSCSVCarriesOnlyTheSecret(t *testing.T) {
	csv := nvsCSV("c2VjcmV0")

	lines := strings.Split(strings.TrimSpace(csv), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, "key,type,encoding,value", lines[0])
	assert.Equal(t, "spiffe,namespace,,", lines[1])
	assert.Equal(t, "device_secret,data,base64,c2VjcmV0", lines[2])
}

func TestGenerateRejectsInvalidDeviceID(t *testing.T) {
	assert.Error(t, runGenerate("star|lord"))
}

func TestGoldenRequestIsDeterministic(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	a, err := goldenRequest("starforge", secret, 1789567213, "46966cf3fdfb685e")
	require.NoError(t, err)
	b, err := goldenRequest("starforge", secret, 1789567213, "46966cf3fdfb685e")
	require.NoError(t, err)

	assert.Equal(t, a, b, "same inputs must produce the same bytes or the firmware cannot be diffed")
}

// Structural assertions rather than a pinned hex blob: these are the properties
// the live server accepted, and they survive a legitimate format change being
// made deliberately.
func TestGoldenRequestMatchesTheAcceptedWireFormat(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	body, err := goldenRequest("starforge", secret, 1789567213, "46966cf3fdfb685e")
	require.NoError(t, err)

	assert.Equal(t, byte(0x00), body[0], "data frame flag")
	assert.Equal(t, uint32(len(body)-5), binary.BigEndian.Uint32(body[1:5]), "frame length must match payload")

	var req pb.FetchX509SVIDRequest
	require.NoError(t, proto.Unmarshal(body[5:], &req))

	require.Len(t, req.Attestations, 1)
	assert.Equal(t, "extension", req.Attestations[0].MethodType)
	assert.Equal(t, "1.0", req.Attestations[0].MethodVersion)

	// proto3 omits an empty cluster_id entirely; a C encoder emitting 0x12 0x00
	// would produce different bytes. Re-marshalling byte-for-byte proves the
	// payload holds exactly these fields and nothing more.
	assert.Empty(t, req.ClusterId)
	remarshaled, err := proto.Marshal(&req)
	require.NoError(t, err)
	assert.Equal(t, body[5:], remarshaled, "payload carries extra or non-canonical fields")

	var e espattest.Evidence
	require.NoError(t, json.Unmarshal(req.Attestations[0].Evidence, &e))
	assert.Equal(t, "starforge", e.DeviceID)
	assert.True(t, e.Verify(secret), "the webhook would reject this evidence")
}

const testTEEKey = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350"

// Same contract as the secret entry: esp32-attestor's loadEnrollment parses it.
func TestTEEEnrollmentJSONMatchesTheWebhookFormat(t *testing.T) {
	body, err := teeEnrollmentJSON("defakto-demo", testTEEKey)
	require.NoError(t, err)

	var parsed map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))

	require.Contains(t, parsed, "defakto-demo")
	assert.Equal(t, map[string]string{"tee_pubkey": testTEEKey}, parsed["defakto-demo"])
}

// The key is pasted from a boot log, so normalise it rather than enrol a
// spelling the webhook compares differently.
func TestTEEEnrollmentJSONNormalisesKeyCase(t *testing.T) {
	body, err := teeEnrollmentJSON("defakto-demo", strings.ToUpper(testTEEKey))
	require.NoError(t, err)

	assert.Contains(t, body, testTEEKey)
}

func TestTEERejectsInvalidDeviceIDOrKey(t *testing.T) {
	assert.Error(t, runTEE("star|lord", testTEEKey))
	assert.Error(t, runTEE("defakto-demo", "04"+strings.Repeat("11", 64)))
	assert.Error(t, runTEE("defakto-demo", "02"+strings.Repeat("ff", 32)))
	assert.NoError(t, runTEE("defakto-demo", testTEEKey))
}
