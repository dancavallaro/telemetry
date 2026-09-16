// esp32-enroll provisions a device secret and exercises the full serverless
// attestation call from a host, so the server side can be validated before any
// firmware exists. Its printed request bytes are the reference the firmware is
// diffed against.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dancavallaro/telemetry/pkg/espattest"
	"github.com/dancavallaro/telemetry/pkg/spirlweb"
	pb "github.com/dancavallaro/telemetry/pkg/spirlweb/serverlessapi"
)

const (
	fetchX509SVIDMethod = "com.spirl.serverless.alpha.SpiffeWorkloadAPI/FetchX509SVID"
	secretBytes         = 32
	callTimeout         = 30 * time.Second
)

const usage = `usage:
  esp32-enroll generate <device_id>
  esp32-enroll attest <endpoint> <device_id> <secret-base64>
  esp32-enroll golden <device_id> <secret-base64> <ts> <nonce>`

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatal(usage)
	}

	switch args[0] {
	case "generate":
		if len(args) != 2 {
			log.Fatal(usage)
		}
		if err := runGenerate(args[1]); err != nil {
			log.Fatalf("generate: %v", err)
		}
	case "attest":
		if len(args) != 4 {
			log.Fatal(usage)
		}
		if err := runAttest(args[1], args[2], args[3]); err != nil {
			log.Fatalf("attest: %v", err)
		}
	case "golden":
		if len(args) != 5 {
			log.Fatal(usage)
		}
		if err := runGolden(args[1], args[2], args[3], args[4]); err != nil {
			log.Fatalf("golden: %v", err)
		}
	default:
		log.Fatal(usage)
	}
}

func runGenerate(deviceID string) error {
	if err := espattest.ValidDeviceID(deviceID); err != nil {
		return err
	}
	secret, err := generateSecret()
	if err != nil {
		return err
	}
	entry, err := enrollmentJSON(deviceID, secret)
	if err != nil {
		return err
	}

	fmt.Printf("device_id: %s\nsecret:    %s\n\n", deviceID, secret)
	fmt.Printf("--- enrollment entry (merge into the /talos-prod/esp32-enrollment parameter) ---\n%s\n\n", entry)
	fmt.Printf("--- nvs.csv (flash to the device) ---\n%s\n", nvsCSV(deviceID, secret))
	return nil
}

// runGolden prints the exact bytes a client must send for fixed inputs, so the
// firmware can be diffed against a reference it can actually reproduce.
func runGolden(deviceID, secretB64, tsArg, nonce string) error {
	secret, err := decodeSecret(deviceID, secretB64)
	if err != nil {
		return err
	}
	ts, err := strconv.ParseInt(tsArg, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing ts: %w", err)
	}

	evidence, err := buildEvidence(deviceID, secret, ts, nonce)
	if err != nil {
		return err
	}
	framed, err := goldenRequest(deviceID, secret, ts, nonce)
	if err != nil {
		return err
	}

	fmt.Printf("evidence: %s\n", evidence)
	fmt.Printf("request:  %s\n", hex.EncodeToString(framed))
	return nil
}

func runAttest(endpoint, deviceID, secretB64 string) error {
	secret, err := decodeSecret(deviceID, secretB64)
	if err != nil {
		return err
	}

	nonce, err := espattest.NewNonce()
	if err != nil {
		return err
	}
	ts := time.Now().Unix()

	evidence, err := buildEvidence(deviceID, secret, ts, nonce)
	if err != nil {
		return err
	}
	fmt.Printf("evidence: %s\n", evidence)

	req := buildRequest(evidence)

	// Printed before the call so a failing attestation still yields the bytes,
	// and reproducible via the golden subcommand with this ts and nonce.
	framed, err := spirlweb.EncodeRequest(req)
	if err != nil {
		return err
	}
	fmt.Printf("request:  %s\n", hex.EncodeToString(framed))
	fmt.Printf("reproduce: esp32-enroll golden %s <secret> %d %s\n\n", deviceID, ts, nonce)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	var resp pb.FetchX509SVIDResponse
	if err := spirlweb.Call(ctx, http.DefaultClient, normalizeEndpoint(endpoint), fetchX509SVIDMethod, req, &resp); err != nil {
		return err
	}

	svids := resp.GetX509Svids().GetSvids()
	if len(svids) == 0 {
		return fmt.Errorf("response contained no SVIDs")
	}
	for _, svid := range svids {
		printSVID(svid)
	}
	return nil
}

func printSVID(svid *pb.X509SVID) {
	fmt.Printf("spiffe_id: %s\n", svid.GetSpiffeId())
	fmt.Printf("cert:      %d bytes\n", len(svid.GetX509Svid()))
	fmt.Printf("key:       %d bytes\n", len(svid.GetX509SvidKey()))
	fmt.Printf("bundle:    %d bytes\n", len(svid.GetBundle()))

	certs, err := x509.ParseCertificates(svid.GetX509Svid())
	if err != nil {
		return
	}
	for _, cert := range certs {
		fmt.Printf("uri_sans:  %v\n", cert.URIs)
		fmt.Printf("not_after: %s (%s from now)\n",
			cert.NotAfter.Format(time.RFC3339), time.Until(cert.NotAfter).Round(time.Second))
	}
}

// buildRequest is shared by attest and golden so the reference bytes can never
// drift from what is actually sent.
func buildRequest(evidence []byte) *pb.FetchX509SVIDRequest {
	return &pb.FetchX509SVIDRequest{
		Attestations: []*pb.MethodAttestation{{
			MethodType:    "extension",
			MethodVersion: "1.0",
			Evidence:      evidence,
		}},
	}
}

func goldenRequest(deviceID string, secret []byte, ts int64, nonce string) ([]byte, error) {
	evidence, err := buildEvidence(deviceID, secret, ts, nonce)
	if err != nil {
		return nil, err
	}
	return spirlweb.EncodeRequest(buildRequest(evidence))
}

func decodeSecret(deviceID, secretB64 string) ([]byte, error) {
	if err := espattest.ValidDeviceID(deviceID); err != nil {
		return nil, err
	}
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("decoding secret: %w", err)
	}
	if len(secret) != secretBytes {
		return nil, fmt.Errorf("secret is %d bytes, want %d", len(secret), secretBytes)
	}
	return secret, nil
}

func generateSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func enrollmentJSON(deviceID, secret string) (string, error) {
	body, err := json.Marshal(map[string]map[string]string{
		deviceID: {"secret": secret},
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// The device reads both keys from NVS, so its ID is provisioned rather than
// derived from the chip.
func nvsCSV(deviceID, secret string) string {
	return "key,type,encoding,value\n" +
		"spiffe,namespace,,\n" +
		fmt.Sprintf("device_id,data,string,%s\n", deviceID) +
		fmt.Sprintf("device_secret,data,base64,%s\n", secret)
}

func buildEvidence(deviceID string, secret []byte, ts int64, nonce string) ([]byte, error) {
	e := espattest.Evidence{DeviceID: deviceID, TS: ts, Nonce: nonce}
	e.MAC = espattest.Sign(e.DeviceID, e.TS, e.Nonce, secret)
	return json.Marshal(e)
}

func normalizeEndpoint(endpoint string) string {
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	return strings.TrimSuffix(endpoint, "/")
}
