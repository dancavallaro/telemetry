package espattest

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Unknown devices and bad signatures share one message so the response cannot be
// used to enumerate which device IDs are enrolled; the real reason is logged.
const rejectInvalid = "invalid evidence"

const rejectStale = "stale evidence"

// Device is one enrolled device's credentials: a shared secret for HMAC
// evidence, a compressed TEE attestation key for TEE evidence, or both.
type Device struct {
	Secret    []byte
	TEEPubKey []byte
}

// Verifier serves the extension webhook contract against an enrollment map.
type Verifier struct {
	Devices map[string]Device
	Skew    time.Duration
	Now     func() time.Time
	Logf    func(string, ...any)

	mu   sync.Mutex
	seen map[string]replayEntry
}

type replayEntry struct {
	at       time.Time
	response attestResponse
}

// request is the body the trust domain server POSTs.
type request struct {
	Meta struct {
		Version string `json:"version"`
	} `json:"_meta"`
	Cluster struct {
		ClusterID string `json:"cluster_id"`
	} `json:"cluster"`
	Payload string `json:"payload"`
}

// attestResponse keys become custom.* attributes, unless "error" is present.
type attestResponse map[string]string

func rejection(reason string) attestResponse {
	return attestResponse{"error": reason}
}

func (v *Verifier) Handler() http.Handler {
	return http.HandlerFunc(v.serve)
}

func (v *Verifier) serve(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		v.logf("undecodable request body: %v", err)
		writeJSON(w, rejection(rejectInvalid))
		return
	}

	raw, err := decodePayload(req.Payload)
	if err != nil {
		v.logf("unparseable payload: %v", err)
		writeJSON(w, rejection(rejectInvalid))
		return
	}

	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		v.logf("unparseable payload: %v", err)
		writeJSON(w, rejection(rejectInvalid))
		return
	}
	switch probe.Format {
	case "":
		writeJSON(w, v.verifyHMAC(raw))
	case TEEFormat:
		writeJSON(w, v.verifyTEE(raw))
	default:
		v.logf("rejecting unknown evidence format %q", probe.Format)
		writeJSON(w, rejection(rejectInvalid))
	}
}

func (v *Verifier) verifyHMAC(raw []byte) attestResponse {
	var e Evidence
	if err := json.Unmarshal(raw, &e); err != nil {
		v.logf("unparseable payload: %v", err)
		return rejection(rejectInvalid)
	}

	device, enrolled := v.Devices[e.DeviceID]
	if !enrolled {
		v.logf("rejecting device_id=%q: not enrolled", e.DeviceID)
		return rejection(rejectInvalid)
	}
	// An empty secret is still a valid HMAC key, so a TEE-only device must
	// never reach Verify.
	if len(device.Secret) == 0 {
		v.logf("rejecting device_id=%q: no secret enrolled", e.DeviceID)
		return rejection(rejectInvalid)
	}
	// Verified before the replay cache is consulted, so a cached success can
	// never be reached without presenting a valid signature.
	if !e.Verify(device.Secret) {
		v.logf("rejecting device_id=%q: signature mismatch", e.DeviceID)
		return rejection(rejectInvalid)
	}
	return v.accept(e.DeviceID, e.TS, e.Nonce, attestResponse{"device_id": e.DeviceID, "anchor": "nvs_secret"})
}

func (v *Verifier) verifyTEE(raw []byte) attestResponse {
	var env teeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		v.logf("unparseable TEE envelope: %v", err)
		return rejection(rejectInvalid)
	}

	device, enrolled := v.Devices[env.DeviceID]
	if !enrolled {
		v.logf("rejecting device_id=%q: not enrolled", env.DeviceID)
		return rejection(rejectInvalid)
	}
	if len(device.TEEPubKey) == 0 {
		v.logf("rejecting device_id=%q: no TEE key enrolled", env.DeviceID)
		return rejection(rejectInvalid)
	}
	// As for HMAC, the signature is checked before the replay cache.
	eat, err := env.verify(device.TEEPubKey)
	if err != nil {
		v.logf("rejecting device_id=%q: %v", env.DeviceID, err)
		return rejection(rejectInvalid)
	}
	return v.accept(env.DeviceID, env.TS, env.Nonce, eat.attributes(env.DeviceID))
}

// accept applies the freshness and replay checks shared by every anchor to
// evidence whose signature has already been verified.
func (v *Verifier) accept(deviceID string, ts int64, nonce string, attrs attestResponse) attestResponse {
	if skew := v.now().Sub(time.Unix(ts, 0)); skew > v.Skew || skew < -v.Skew {
		v.logf("rejecting device_id=%q: clock skew %s exceeds %s", deviceID, skew, v.Skew)
		return rejection(rejectStale)
	}
	return v.resultFor(deviceID, nonce, attrs)
}

// resultFor replays the stored result for a repeated nonce. The trust domain
// server retries 5xx, so a repeat must succeed identically rather than reject.
func (v *Verifier) resultFor(deviceID, nonce string, attrs attestResponse) attestResponse {
	// Keyed by anchor too, so evidence from a weaker anchor can never be
	// served a stronger one's cached attributes.
	key := attrs["anchor"] + "|" + deviceID + "|" + nonce
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]replayEntry{}
	}
	if entry, ok := v.seen[key]; ok {
		v.logf("replaying stored result for device_id=%q", deviceID)
		return entry.response
	}
	for k, entry := range v.seen {
		if now.Sub(entry.at) > 2*v.Skew {
			delete(v.seen, k)
		}
	}

	v.seen[key] = replayEntry{at: now, response: attrs}
	v.logf("accepting device_id=%q", deviceID)
	return attrs
}

// decodePayload accepts the payload verbatim or base64-encoded: Defakto
// documents base64 but currently sends the bytes as-is.
func decodePayload(payload string) ([]byte, error) {
	if json.Valid([]byte(payload)) {
		return []byte(payload), nil
	}
	return base64.StdEncoding.DecodeString(payload)
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) logf(format string, args ...any) {
	if v.Logf != nil {
		v.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func writeJSON(w http.ResponseWriter, resp attestResponse) {
	// Rejection is a non-empty error field with HTTP 200; a non-200 makes the
	// server give up without reading the reason.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed writing response: %v", err)
	}
}
