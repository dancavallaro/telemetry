// Package espattest is the attestation contract shared by the ESP32 firmware and
// the esp32-attestor webhook: how evidence is built, signed, and verified.
//
// Evidence must stay 7-bit ASCII. The trust domain server marshals it into a JSON
// string on its way to the webhook and replaces every byte that is not valid
// UTF-8, so raw binary does not survive the trip.
package espattest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

const nonceBytes = 8

// Evidence is the proof a device presents; it travels as the attestation's
// evidence bytes and arrives at the webhook as JSON.
type Evidence struct {
	DeviceID string `json:"device_id"`
	TS       int64  `json:"ts"`
	Nonce    string `json:"nonce"`
	MAC      string `json:"mac"`
}

// Sign returns the hex HMAC-SHA256 binding a device to a timestamp and nonce.
func Sign(deviceID string, ts int64, nonce string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingString(deviceID, ts, nonce)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether the evidence was signed with secret.
func (e Evidence) Verify(secret []byte) bool {
	got, err := hex.DecodeString(e.MAC)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(Sign(e.DeviceID, e.TS, e.Nonce, secret))
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

// NewNonce returns 16 hex characters of randomness.
func NewNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DeviceID and Nonce are hex, so "|" cannot appear in either and the joined
// string is unambiguous.
func signingString(deviceID string, ts int64, nonce string) string {
	return deviceID + "|" + strconv.FormatInt(ts, 10) + "|" + nonce
}
