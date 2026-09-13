// esp32-attestor is a skeleton Defakto serverless attestation extension.
//
// It accepts essentially any evidence and echoes back attributes, which the
// trust domain server exposes to svidPolicy templates as custom.*. The real
// attestation logic is deliberately absent.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"
)

var (
	addr         = flag.String("addr", ":8443", "Address:port to serve the webhook on")
	tlsCert      = flag.String("tlsCert", "/tls/tls.crt", "Path to the serving certificate")
	tlsKey       = flag.String("tlsKey", "/tls/tls.key", "Path to the serving private key")
	rejectDevice = flag.String("rejectDevice", "rejectme", "Device ID that exercises the rejection path")
)

const defaultDeviceID = "unknown"

// request is the body the trust domain server POSTs to an extension webhook.
type request struct {
	Meta struct {
		Version string `json:"version"`
	} `json:"_meta"`
	Cluster struct {
		ClusterID string `json:"cluster_id"`
	} `json:"cluster"`
	Payload string `json:"payload"`
}

// response keys become custom.* attributes, unless error is non-empty.
type response struct {
	Error    string `json:"error,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Anchor   string `json:"anchor,omitempty"`
}

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", handleAttest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("serving attestation webhook on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("attest: undecodable request body: %v", err)
		writeJSON(w, response{Error: "malformed request"})
		return
	}

	log.Printf("attest: meta.version=%q cluster_id=%q", req.Meta.Version, req.Cluster.ClusterID)
	evidence := logPayloadEncoding(req.Payload)

	deviceID := defaultDeviceID
	var parsed struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(evidence, &parsed); err == nil && parsed.DeviceID != "" {
		deviceID = parsed.DeviceID
	} else {
		log.Printf("attest: evidence had no device_id, defaulting to %q", defaultDeviceID)
	}

	if deviceID == *rejectDevice {
		log.Printf("attest: rejecting device_id=%q", deviceID)
		writeJSON(w, response{Error: "device is not allowed to attest"})
		return
	}

	log.Printf("attest: accepting device_id=%q", deviceID)
	writeJSON(w, response{DeviceID: deviceID, Anchor: "none"})
}

// logPayloadEncoding answers whether evidence is base64-encoded once or twice on
// its way here, and returns the bytes at whichever depth stops being base64.
func logPayloadEncoding(payload string) []byte {
	log.Printf("attest: payload raw     = %q", payload)

	once, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("attest: payload is not base64 at all (%v) — evidence passed through verbatim", err)
		return []byte(payload)
	}
	log.Printf("attest: payload decoded once  = %q", string(once))

	twice, err := base64.StdEncoding.DecodeString(string(once))
	if err != nil {
		log.Printf("attest: ENCODING ANSWER: base64 encoded ONCE (second decode failed: %v)", err)
		return once
	}
	log.Printf("attest: payload decoded twice = %q", string(twice))
	log.Printf("attest: ENCODING ANSWER: base64 encoded TWICE")
	return twice
}

func writeJSON(w http.ResponseWriter, resp response) {
	// Rejection is a non-empty error field with HTTP 200; non-200 means no retry.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("attest: failed writing response: %v", err)
	}
}
