// esp32-attestor is the Defakto serverless attestation extension webhook for
// ESP32 devices. It verifies an HMAC-over-timestamp proof against a per-device
// shared secret and returns attributes that become the device's SPIFFE ID.
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

// enrolledDevice is one entry of the enrollment file.
type enrolledDevice struct {
	Secret string `json:"secret"`
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
		secret, err := base64.StdEncoding.DecodeString(entry.Secret)
		if err != nil {
			return nil, fmt.Errorf("decoding secret for %s: %w", deviceID, err)
		}
		if len(secret) != secretBytes {
			return nil, fmt.Errorf("secret for %s is %d bytes, want %d bytes", deviceID, len(secret), secretBytes)
		}
		devices[deviceID] = espattest.Device{Secret: secret}
	}
	return devices, nil
}
