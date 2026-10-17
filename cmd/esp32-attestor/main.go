// esp32-attestor is the Defakto serverless attestation extension webhook for
// ESP32 devices. It verifies an HMAC-over-timestamp proof against a per-device
// shared secret, or an ESP-TEE attestation token against an enrolled TEE key,
// and returns attributes that become the device's SPIFFE ID.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dancavallaro/telemetry/pkg/espattest"
)

// secretBytes is the provisioned per-device secret length.
const secretBytes = 32

var (
	addr       = flag.String("addr", ":8443", "Address:port to serve the webhook on")
	tlsCert    = flag.String("tlsCert", "/tls/tls.crt", "Path to the serving certificate")
	tlsKey     = flag.String("tlsKey", "/tls/tls.key", "Path to the serving private key")
	enrollment = flag.String("enrollment", "/enrollment/enrollment.json", "Path to the enrollment file")
	skew       = flag.Duration("skew", 60*time.Second, "Maximum accepted clock skew on evidence timestamps")
)

// enrolledDevice is one entry of the enrollment file; each needs at least one
// of the two.
type enrolledDevice struct {
	Secret    string `json:"secret,omitempty"`
	TEEPubKey string `json:"tee_pubkey,omitempty"`
}

func main() {
	flag.Parse()

	devices, err := loadEnrollment(*enrollment)
	if err != nil {
		log.Fatalf("loading enrollment: %v", err)
	}
	log.Printf("loaded %d enrolled devices from %s", len(devices), *enrollment)

	verifier := &espattest.Verifier{Devices: devices, Skew: *skew}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(verifier),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("serving attestation webhook on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
}

func newMux(verifier *espattest.Verifier) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("POST /attest", verifier.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	return mux
}

// Enrollment is read once at startup, so adding a device needs a pod restart.
func loadEnrollment(path string) (map[string]espattest.Device, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries map[string]enrolledDevice
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s contains no devices", path)
	}

	devices := make(map[string]espattest.Device, len(entries))
	for deviceID, entry := range entries {
		if err := espattest.ValidDeviceID(deviceID); err != nil {
			return nil, err
		}
		device, err := parseEnrolledDevice(entry)
		if err != nil {
			return nil, fmt.Errorf("enrollment for %s: %w", deviceID, err)
		}
		devices[deviceID] = device
	}
	return devices, nil
}

func parseEnrolledDevice(entry enrolledDevice) (espattest.Device, error) {
	var device espattest.Device
	if entry.Secret == "" && entry.TEEPubKey == "" {
		return device, fmt.Errorf("needs a secret, a tee_pubkey, or both")
	}
	if entry.Secret != "" {
		secret, err := base64.StdEncoding.DecodeString(entry.Secret)
		if err != nil {
			return device, fmt.Errorf("decoding secret: %w", err)
		}
		if len(secret) != secretBytes {
			return device, fmt.Errorf("secret is %d bytes, want %d bytes", len(secret), secretBytes)
		}
		device.Secret = secret
	}
	if entry.TEEPubKey != "" {
		key, err := espattest.ParseTEEPubKey(entry.TEEPubKey)
		if err != nil {
			return device, err
		}
		device.TEEPubKey = key
	}
	return device, nil
}
