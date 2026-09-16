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

// Device is one enrolled device's shared secret and reported attributes.
type Device struct {
	Secret []byte
	Model  string
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

// attestResponse keys become custom.* attributes, unless Error is non-empty.
type attestResponse struct {
	Error    string `json:"error,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Anchor   string `json:"anchor,omitempty"`
	Model    string `json:"model,omitempty"`
}

func (v *Verifier) Handler() http.Handler {
	return http.HandlerFunc(v.serve)
}

func (v *Verifier) serve(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		v.logf("undecodable request body: %v", err)
		writeJSON(w, attestResponse{Error: rejectInvalid})
		return
	}

	e, err := parseEvidence(req.Payload)
	if err != nil {
		v.logf("unparseable payload: %v", err)
		writeJSON(w, attestResponse{Error: rejectInvalid})
		return
	}

	device, enrolled := v.Devices[e.DeviceID]
	if !enrolled {
		v.logf("rejecting device_id=%q: not enrolled", e.DeviceID)
		writeJSON(w, attestResponse{Error: rejectInvalid})
		return
	}
	// Verified before the replay cache is consulted, so a cached success can
	// never be reached without presenting a valid signature.
	if !e.Verify(device.Secret) {
		v.logf("rejecting device_id=%q: signature mismatch", e.DeviceID)
		writeJSON(w, attestResponse{Error: rejectInvalid})
		return
	}
	if skew := v.now().Sub(time.Unix(e.TS, 0)); skew > v.Skew || skew < -v.Skew {
		v.logf("rejecting device_id=%q: clock skew %s exceeds %s", e.DeviceID, skew, v.Skew)
		writeJSON(w, attestResponse{Error: rejectStale})
		return
	}

	writeJSON(w, v.resultFor(e, device))
}

// resultFor replays the stored result for a repeated nonce. The trust domain
// server retries 5xx, so a repeat must succeed identically rather than reject.
func (v *Verifier) resultFor(e Evidence, device Device) attestResponse {
	key := e.DeviceID + "|" + e.Nonce
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]replayEntry{}
	}
	if entry, ok := v.seen[key]; ok {
		v.logf("replaying stored result for device_id=%q", e.DeviceID)
		return entry.response
	}
	for k, entry := range v.seen {
		if now.Sub(entry.at) > 2*v.Skew {
			delete(v.seen, k)
		}
	}

	resp := attestResponse{DeviceID: e.DeviceID, Anchor: "nvs_secret", Model: device.Model}
	v.seen[key] = replayEntry{at: now, response: resp}
	v.logf("accepting device_id=%q", e.DeviceID)
	return resp
}

// parseEvidence accepts the payload verbatim or base64-encoded: Defakto
// documents base64 but currently sends the bytes as-is.
func parseEvidence(payload string) (Evidence, error) {
	var e Evidence
	if err := json.Unmarshal([]byte(payload), &e); err == nil {
		return e, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(decoded, &e)
	return e, err
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
