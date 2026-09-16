package espattest

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestSignIsDeterministicAndKeyDependent(t *testing.T) {
	got := Sign("a1b2c3d4e5f6", 1789200000, "deadbeefcafe0001", testSecret)

	assert.Equal(t, got, Sign("a1b2c3d4e5f6", 1789200000, "deadbeefcafe0001", testSecret),
		"Sign is not deterministic")
	assert.NotEqual(t, got, Sign("a1b2c3d4e5f6", 1789200000, "deadbeefcafe0001", []byte("wrong-secret-wrong-secret-wrong!")),
		"Sign ignored the secret")
	assert.Len(t, got, 64, "want 64 hex chars of HMAC-SHA256")
}

// Guards against a signing string that drops a field or lets two different
// inputs collide.
func TestSignCoversEveryField(t *testing.T) {
	base := Sign("a1b2c3d4e5f6", 1789200000, "deadbeefcafe0001", testSecret)

	assert.NotEqual(t, base, Sign("ffffffffffff", 1789200000, "deadbeefcafe0001", testSecret), "device_id not signed")
	assert.NotEqual(t, base, Sign("a1b2c3d4e5f6", 1789200001, "deadbeefcafe0001", testSecret), "ts not signed")
	assert.NotEqual(t, base, Sign("a1b2c3d4e5f6", 1789200000, "deadbeefcafe0002", testSecret), "nonce not signed")
}

func TestVerifyAcceptsGenuineEvidence(t *testing.T) {
	e := Evidence{DeviceID: "a1b2c3d4e5f6", TS: 1789200000, Nonce: "deadbeefcafe0001"}
	e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)

	assert.True(t, e.Verify(testSecret))
}

func TestVerifyRejectsTamperedEvidence(t *testing.T) {
	good := Evidence{DeviceID: "a1b2c3d4e5f6", TS: 1789200000, Nonce: "deadbeefcafe0001"}
	good.MAC = Sign(good.DeviceID, good.TS, good.Nonce, testSecret)

	tests := map[string]func(e *Evidence){
		"device_id": func(e *Evidence) { e.DeviceID = "ffffffffffff" },
		"ts":        func(e *Evidence) { e.TS = 1789200001 },
		"nonce":     func(e *Evidence) { e.Nonce = "deadbeefcafe0002" },
		"mac":       func(e *Evidence) { e.MAC = "00000000000000000000000000000000000000000000000000000000000000ff" },
		"empty mac": func(e *Evidence) { e.MAC = "" },
		"bad hex":   func(e *Evidence) { e.MAC = "zz" },
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			e := good
			tamper(&e)
			assert.False(t, e.Verify(testSecret))
		})
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	e := Evidence{DeviceID: "a1b2c3d4e5f6", TS: 1789200000, Nonce: "deadbeefcafe0001"}
	e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)

	assert.False(t, e.Verify([]byte("wrong-secret-wrong-secret-wrong!")))
}

// The trust domain server marshals evidence into a JSON string and replaces any
// byte that is not valid UTF-8, so bytes >= 0x80 never survive the trip. Keeping
// evidence 7-bit ASCII is load-bearing, not cosmetic.
func TestEvidenceJSONIsASCIIOnly(t *testing.T) {
	nonce, err := NewNonce()
	require.NoError(t, err)

	e := Evidence{DeviceID: "a1b2c3d4e5f6", TS: 1789200000, Nonce: nonce}
	e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)

	body, err := json.Marshal(e)
	require.NoError(t, err)

	for i, b := range body {
		require.Less(t, b, byte(0x80), "byte %d of %q is not 7-bit ASCII", i, body)
	}
}

func TestNewNonceIsSixteenHexCharsAndUnique(t *testing.T) {
	a, err := NewNonce()
	require.NoError(t, err)
	b, err := NewNonce()
	require.NoError(t, err)

	assert.Len(t, a, 16)
	assert.NotEqual(t, a, b)
	assert.Regexp(t, "^[0-9a-f]{16}$", a)
}
