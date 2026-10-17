package espattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	goldenDeviceID = "defakto-demo"
	goldenTS       = 1792200000
	goldenNonce    = "0011223344556677"

	// The XIAO's attestation key, which signed the golden envelope.
	xiaoTEEKey = "02cded7398be59dd931161ccf6ecc7482894f7411e6b5c768f5941e838ce12cdba"
	// The Waveshare's: a genuine key that did not sign the golden.
	waveshareTEEKey = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350"
)

var goldenNow = time.Unix(goldenTS, 0)

// Captured from the XIAO's TEE; esp32-spiffe-rust's tee_envelope_golden test
// checks the same file. If this fails, the format has drifted; don't recapture
// it to make the test pass.
func goldenEnvelope(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("testdata/tee_envelope_golden.json")
	require.NoError(t, err)
	return strings.TrimSpace(string(body))
}

func mustTEEKey(t *testing.T, hexKey string) []byte {
	t.Helper()
	key, err := ParseTEEPubKey(hexKey)
	require.NoError(t, err)
	return key
}

func newTEEVerifier(t *testing.T, key []byte) *Verifier {
	t.Helper()
	return &Verifier{
		Devices: map[string]Device{goldenDeviceID: {TEEPubKey: key}},
		Skew:    60 * time.Second,
		Now:     func() time.Time { return goldenNow },
		Logf:    t.Logf,
	}
}

func TestTEEGoldenEnvelopeVerifies(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))

	got := postPayload(t, v, goldenEnvelope(t))

	assert.Equal(t, map[string]string{
		"device_id":          goldenDeviceID,
		"anchor":             "tee",
		"app_version":        "0.1.0",
		"app_digest":         "d97d0bc6391637f6097a89294b4a7a0908a9f0036cd5d423e160862953c1df9d",
		"app_secure_version": "0",
		"tee_version":        "1.0.0",
		"tee_digest":         "ac91a50042bd5df20c229d5f2cdf95c80a1ad59296fb2c777896a2e615235d66",
		"bootloader_digest":  "8415ba134050d3a0aaf53f457579a3052edf886945dbe685bd7261006a145501",
		"idf_version":        "5.5.5",
		"secure_boot":        "false",
	}, got)
}

func TestTEERejectsTamperedEATByte(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
	tampered := strings.Replace(goldenEnvelope(t), `"ver":"0.1.0"`, `"ver":"0.2.0"`, 1)

	got := postPayload(t, v, tampered)

	assert.Equal(t, rejectInvalid, got["error"])
}

func TestTEERejectsKeyOtherThanEnrolled(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, waveshareTEEKey))

	got := postPayload(t, v, goldenEnvelope(t))

	assert.Equal(t, rejectInvalid, got["error"])
}

func TestTEERejectsStaleTimestamp(t *testing.T) {
	tests := map[string]time.Time{
		"too old":    goldenNow.Add(61 * time.Second),
		"too future": goldenNow.Add(-61 * time.Second),
	}
	for name, now := range tests {
		t.Run(name, func(t *testing.T) {
			v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
			v.Now = func() time.Time { return now }

			got := postPayload(t, v, goldenEnvelope(t))

			assert.Equal(t, rejectStale, got["error"])
		})
	}
}

// ts and nonce sit outside the signed token, bound to it only through eat.nonce.
func TestTEERejectsEnvelopeFieldsNotBoundToToken(t *testing.T) {
	tests := map[string][2]string{
		"nonce":     {`"nonce":"0011223344556677"`, `"nonce":"0011223344556678"`},
		"ts":        {`"ts":1792200000`, `"ts":1792200001`},
		"device_id": {`"device_id":"defakto-demo"`, `"device_id":"defakto-demo2"`},
	}
	for name, swap := range tests {
		t.Run(name, func(t *testing.T) {
			v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
			v.Devices["defakto-demo2"] = v.Devices[goldenDeviceID]
			envelope := strings.Replace(goldenEnvelope(t), swap[0], swap[1], 1)
			require.NotEqual(t, goldenEnvelope(t), envelope)

			got := postPayload(t, v, envelope)

			assert.Equal(t, rejectInvalid, got["error"])
		})
	}
}

// The server retries 5xx, so a repeat replays the original result, as for HMAC.
func TestTEERepeatedEnvelopeReplaysOriginalResult(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))

	first := postPayload(t, v, goldenEnvelope(t))
	second := postPayload(t, v, goldenEnvelope(t))

	assert.Empty(t, first["error"])
	assert.Equal(t, first, second)
}

// A cached nonce must not let a forged token through on its coattails.
func TestTEEReplayWithTamperedTokenIsRejected(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
	require.Empty(t, postPayload(t, v, goldenEnvelope(t))["error"])

	tampered := strings.Replace(goldenEnvelope(t), `"ver":"0.1.0"`, `"ver":"0.2.0"`, 1)
	got := postPayload(t, v, tampered)

	assert.Equal(t, rejectInvalid, got["error"])
}

func TestTEERejectsUnenrolledDeviceAndDeviceWithoutTEEKey(t *testing.T) {
	tests := map[string]map[string]Device{
		"unknown device": {"someone-else": {TEEPubKey: mustTEEKey(t, xiaoTEEKey)}},
		"secret only":    {goldenDeviceID: {Secret: testSecret}},
	}
	for name, devices := range tests {
		t.Run(name, func(t *testing.T) {
			v := newTEEVerifier(t, nil)
			v.Devices = devices

			got := postPayload(t, v, goldenEnvelope(t))

			assert.Equal(t, rejectInvalid, got["error"])
		})
	}
}

func TestTEERejectsUnknownFormat(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
	envelope := strings.Replace(goldenEnvelope(t), `"format":"esp-tee-eat/1"`, `"format":"esp-tee-eat/2"`, 1)

	got := postPayload(t, v, envelope)

	assert.Equal(t, rejectInvalid, got["error"])
}

// An empty secret is a valid HMAC key, so a TEE-only device must not fall
// through to HMAC verification with one.
func TestHMACEvidenceRejectedForDeviceWithoutSecret(t *testing.T) {
	v := newTestVerifier(t)
	v.Devices[testDeviceID] = Device{TEEPubKey: mustTEEKey(t, xiaoTEEKey)}

	_, got := post(t, v, genuineEvidence(t, func(e *Evidence) {
		e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, nil)
	}), nil)

	assert.Equal(t, rejectInvalid, got["error"])
}

// Self-signed tokens isolate checks the golden can't reach without also
// breaking its signature.
type testToken struct {
	header, publicKey string
	nonce             string
	clientID          uint32
	signer            *ecdsa.PrivateKey
}

func newTestToken(signer *ecdsa.PrivateKey) testToken {
	return testToken{
		header:    `{"magic":"44fef7cc","encr_alg":"","sign_alg":"ecdsa_secp256r1_sha256","key_id":"tee_att_key0"}`,
		publicKey: fmt.Sprintf(`{"compressed":"%x"}`, compressedKey(&signer.PublicKey)),
		nonce:     goldenNonce,
		clientID:  0x0DEFA470,
		signer:    signer,
	}
}

func (tok testToken) envelope(t *testing.T) string {
	t.Helper()
	eat := fmt.Sprintf(`{"nonce":%d,"client_id":%d,"sw_claims":{}}`,
		int32(teeTestNonce(goldenDeviceID, goldenTS, tok.nonce)), int32(tok.clientID))
	digest := sha256.Sum256([]byte(tok.header + eat + tok.publicKey))
	r, s, err := ecdsa.Sign(rand.Reader, tok.signer, digest[:])
	require.NoError(t, err)
	return fmt.Sprintf(`{"format":"esp-tee-eat/1","device_id":%q,"ts":%d,"nonce":%q,"token":{"header":%s,"eat":%s,"public_key":%s,"sign":{"r":"%064x","s":"%064x"}}}`,
		goldenDeviceID, goldenTS, tok.nonce, tok.header, eat, tok.publicKey, r, s)
}

func teeTestNonce(deviceID string, ts int64, nonce string) uint32 {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", deviceID, ts, nonce)))
	return binary.BigEndian.Uint32(digest[:4])
}

func compressedKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
}

func newSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestTEEAcceptsSelfSignedToken(t *testing.T) {
	signer := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&signer.PublicKey))

	got := postPayload(t, v, newTestToken(signer).envelope(t))

	assert.Empty(t, got["error"])
	assert.Equal(t, "tee", got["anchor"])
}

func TestTEERejectsWrongClientID(t *testing.T) {
	signer := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&signer.PublicKey))
	tok := newTestToken(signer)
	tok.clientID = 0x0DEFA471

	got := postPayload(t, v, tok.envelope(t))

	assert.Equal(t, rejectInvalid, got["error"])
}

// A token that names the enrolled key but was signed by another must fail on
// the signature, not pass on the key comparison.
func TestTEERejectsTokenSignedByOtherKeyClaimingEnrolledKey(t *testing.T) {
	enrolled := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&enrolled.PublicKey))
	tok := newTestToken(enrolled)
	tok.signer = newSigner(t)

	got := postPayload(t, v, tok.envelope(t))

	assert.Equal(t, rejectInvalid, got["error"])
}

func TestTEERejectsTokenNamingAnotherKey(t *testing.T) {
	enrolled := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&enrolled.PublicKey))
	tok := newTestToken(enrolled)
	tok.publicKey = fmt.Sprintf(`{"compressed":"%x"}`, compressedKey(&newSigner(t).PublicKey))

	got := postPayload(t, v, tok.envelope(t))

	assert.Equal(t, rejectInvalid, got["error"])
}

func TestTEERejectsWrongSignAlg(t *testing.T) {
	signer := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&signer.PublicKey))
	tok := newTestToken(signer)
	tok.header = strings.Replace(tok.header, "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", 1)

	got := postPayload(t, v, tok.envelope(t))

	assert.Equal(t, rejectInvalid, got["error"])
}

// The TEE prints eat.nonce as a signed int32, so half of all nonces are negative.
func TestTEEAcceptsNegativeEATNonce(t *testing.T) {
	signer := newSigner(t)
	v := newTEEVerifier(t, compressedKey(&signer.PublicKey))
	tok := newTestToken(signer)
	for n := 0; int32(teeTestNonce(goldenDeviceID, goldenTS, tok.nonce)) >= 0; n++ {
		tok.nonce = fmt.Sprintf("%016x", n)
	}

	got := postPayload(t, v, tok.envelope(t))

	assert.Empty(t, got["error"])
}

func TestParseTEEPubKeyAcceptsCompressedPoint(t *testing.T) {
	key, err := ParseTEEPubKey(xiaoTEEKey)

	require.NoError(t, err)
	assert.Equal(t, xiaoTEEKey, hex.EncodeToString(key))
}

func TestParseTEEPubKeyRejectsNonPoints(t *testing.T) {
	tests := map[string]string{
		"empty":        "",
		"bad hex":      "zz",
		"uncompressed": "04" + strings.Repeat("11", 64),
		"short":        xiaoTEEKey[:64],
		"off curve":    "02" + strings.Repeat("ff", 32),
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTEEPubKey(key)
			assert.Error(t, err)
		})
	}
}

// HMAC and TEE share the replay cache, so an HMAC request reusing a TEE
// envelope's nonce must not be served the TEE's attributes.
func TestHMACEvidenceReusingTEENonceDoesNotGetTEEAttributes(t *testing.T) {
	v := newTEEVerifier(t, mustTEEKey(t, xiaoTEEKey))
	v.Devices[goldenDeviceID] = Device{Secret: testSecret, TEEPubKey: mustTEEKey(t, xiaoTEEKey)}
	require.Equal(t, "tee", postPayload(t, v, goldenEnvelope(t))["anchor"])

	e := Evidence{DeviceID: goldenDeviceID, TS: goldenTS, Nonce: goldenNonce}
	e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)
	_, got := post(t, v, e, nil)

	assert.Equal(t, map[string]string{"device_id": goldenDeviceID, "anchor": "nvs_secret"}, got)
}
