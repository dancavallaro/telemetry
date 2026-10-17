package espattest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDeviceID = "a1b2c3d4e5f6"

var testNow = time.Unix(1789200000, 0)

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	return &Verifier{
		Devices: map[string]Device{
			testDeviceID: {Secret: testSecret},
		},
		Skew: 60 * time.Second,
		Now:  func() time.Time { return testNow },
		Logf: t.Logf,
	}
}

func genuineEvidence(t *testing.T, mutate func(*Evidence)) Evidence {
	t.Helper()
	nonce, err := NewNonce()
	require.NoError(t, err)
	e := Evidence{DeviceID: testDeviceID, TS: testNow.Unix(), Nonce: nonce}
	e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)
	if mutate != nil {
		mutate(&e)
	}
	return e
}

// post sends the evidence exactly as the trust domain server does: the evidence
// JSON verbatim inside the payload field.
func post(t *testing.T, v *Verifier, e Evidence, encodePayload func([]byte) string) (int, map[string]string) {
	t.Helper()
	raw, err := json.Marshal(e)
	require.NoError(t, err)

	payload := string(raw)
	if encodePayload != nil {
		payload = encodePayload(raw)
	}
	return postRaw(t, v, payload)
}

func postPayload(t *testing.T, v *Verifier, payload string) map[string]string {
	t.Helper()
	code, got := postRaw(t, v, payload)
	require.Equal(t, http.StatusOK, code)
	return got
}

func postRaw(t *testing.T, v *Verifier, payload string) (int, map[string]string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"_meta":   map[string]string{"version": "1.0"},
		"cluster": map[string]string{"cluster_id": ""},
		"payload": payload,
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	v.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(string(body))))

	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got), "response was not JSON: %s", rec.Body.String())
	return rec.Code, got
}

func TestAcceptsGenuineEvidence(t *testing.T) {
	code, got := post(t, newTestVerifier(t), genuineEvidence(t, nil), nil)

	assert.Equal(t, http.StatusOK, code)
	assert.Empty(t, got["error"])
	assert.Equal(t, testDeviceID, got["device_id"])
	assert.Equal(t, "nvs_secret", got["anchor"])
	assert.NotContains(t, got, "model", "model was dropped from the attributes")
}

// Defakto documents payload as base64 but sends it verbatim; accept both so a
// fix on their side does not break us.
func TestAcceptsBase64EncodedPayload(t *testing.T) {
	code, got := post(t, newTestVerifier(t), genuineEvidence(t, nil), func(raw []byte) string {
		return base64.StdEncoding.EncodeToString(raw)
	})

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, testDeviceID, got["device_id"])
}

// A rejection is a non-empty error field with HTTP 200; a non-200 would make the
// server give up without reading the reason.
func TestRejectionsUseHTTP200(t *testing.T) {
	code, got := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.DeviceID = "ffffffffffff"
	}), nil)

	assert.Equal(t, http.StatusOK, code)
	assert.NotEmpty(t, got["error"])
	assert.Empty(t, got["device_id"])
}

func TestRejectsUnknownDevice(t *testing.T) {
	_, got := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.DeviceID = "ffffffffffff"
	}), nil)

	assert.NotEmpty(t, got["error"])
}

func TestRejectsBadMAC(t *testing.T) {
	_, got := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, []byte("wrong-secret-wrong-secret-wrong!"))
	}), nil)

	assert.NotEmpty(t, got["error"])
}

// Enumeration oracle: an unknown device and a bad signature must be
// indistinguishable to an unauthenticated caller.
func TestRejectionDoesNotRevealWhetherDeviceIsEnrolled(t *testing.T) {
	_, unknown := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.DeviceID = "ffffffffffff"
	}), nil)
	_, badMAC := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, []byte("wrong-secret-wrong-secret-wrong!"))
	}), nil)

	assert.Equal(t, unknown["error"], badMAC["error"])
}

func TestRejectsTimestampOutsideSkew(t *testing.T) {
	tests := map[string]int64{
		"too old":    testNow.Unix() - 61,
		"too future": testNow.Unix() + 61,
	}
	for name, ts := range tests {
		t.Run(name, func(t *testing.T) {
			_, got := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
				e.TS = ts
				e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)
			}), nil)

			assert.NotEmpty(t, got["error"])
		})
	}
}

func TestAcceptsTimestampInsideSkew(t *testing.T) {
	_, got := post(t, newTestVerifier(t), genuineEvidence(t, func(e *Evidence) {
		e.TS = testNow.Unix() - 59
		e.MAC = Sign(e.DeviceID, e.TS, e.Nonce, testSecret)
	}), nil)

	assert.Empty(t, got["error"])
}

// The server retries 5xx, so a repeat of the same nonce must replay the original
// result rather than reject it as a replay.
func TestRepeatedNonceReplaysOriginalResult(t *testing.T) {
	v := newTestVerifier(t)
	e := genuineEvidence(t, nil)

	code1, first := post(t, v, e, nil)
	code2, second := post(t, v, e, nil)

	assert.Equal(t, code1, code2)
	assert.Equal(t, first, second)
	assert.Empty(t, second["error"])
}

func TestRejectsMalformedPayload(t *testing.T) {
	v := newTestVerifier(t)
	body := `{"_meta":{"version":"1.0"},"cluster":{"cluster_id":""},"payload":"not json at all"}`

	rec := httptest.NewRecorder()
	v.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(body)))

	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, got["error"])
}

func TestRejectsMalformedRequestBody(t *testing.T) {
	v := newTestVerifier(t)

	rec := httptest.NewRecorder()
	v.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader("{")))

	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.NotEmpty(t, got["error"])
}
