// svid-fetch calls Defakto's serverless SPIFFE Workload API over gRPC-Web and
// prints the X.509 SVID it gets back. Local development tool; not containerized.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dancavallaro/telemetry/pkg/spirlweb"
	pb "github.com/dancavallaro/telemetry/pkg/spirlweb/serverlessapi"
)

const fetchX509SVIDMethod = "com.spirl.serverless.alpha.SpiffeWorkloadAPI/FetchX509SVID"

var (
	endpoint    = flag.String("endpoint", "https://defakto.o.cavnet.cloud", "Base URL of the serverless SPIFFE API")
	deviceID    = flag.String("deviceId", "testdev01", "Device ID to claim in the evidence")
	evidence    = flag.String("evidence", "", "Raw evidence to send; defaults to a JSON object built from -deviceId")
	evidenceHex = flag.String("evidenceHex", "", "Evidence as hex, for probing how binary evidence survives the wire; overrides -evidence")
	clusterID   = flag.String("clusterId", "", "Cluster ID to send in the request")
	outDir      = flag.String("outDir", "", "If set, write svid.pem, key.pem and bundle.pem to this directory")
	timeout     = flag.Duration("timeout", 30*time.Second, "Overall request timeout")
)

func main() {
	flag.Parse()

	body, err := buildEvidence()
	if err != nil {
		log.Fatal(err)
	}

	req := &pb.FetchX509SVIDRequest{
		Attestations: []*pb.MethodAttestation{{
			MethodType:    "extension",
			MethodVersion: "1.0",
			Evidence:      body,
		}},
		ClusterId: *clusterID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var resp pb.FetchX509SVIDResponse
	if err := spirlweb.Call(ctx, http.DefaultClient, *endpoint, fetchX509SVIDMethod, req, &resp); err != nil {
		log.Fatalf("FetchX509SVID failed: %v", err)
	}

	svids := resp.GetX509Svids().GetSvids()
	if len(svids) == 0 {
		log.Fatal("response contained no SVIDs")
	}
	for i, svid := range svids {
		printSVID(i, svid)
	}
	if *outDir != "" {
		if err := writePEM(*outDir, svids[0]); err != nil {
			log.Fatalf("writing PEM files: %v", err)
		}
		log.Printf("wrote svid.pem, key.pem and bundle.pem to %s", *outDir)
	}
}

// buildEvidence also logs what it built, since binary evidence must not be
// printed raw to a terminal.
func buildEvidence() ([]byte, error) {
	if *evidenceHex != "" {
		body, err := hex.DecodeString(strings.TrimSpace(*evidenceHex))
		if err != nil {
			return nil, fmt.Errorf("decoding -evidenceHex: %w", err)
		}
		log.Printf("sending evidence: %d bytes, hex %s", len(body), hex.EncodeToString(body))
		return body, nil
	}
	body := *evidence
	if body == "" {
		body = fmt.Sprintf(`{"device_id":%q}`, *deviceID)
	}
	log.Printf("sending evidence: %s", body)
	return []byte(body), nil
}

func printSVID(i int, svid *pb.X509SVID) {
	fmt.Printf("\nSVID %d\n", i)
	fmt.Printf("  spiffe_id: %s\n", svid.GetSpiffeId())
	if h := svid.GetHint(); h != "" {
		fmt.Printf("  hint:      %s\n", h)
	}

	certs, err := parseCerts(svid.GetX509Svid())
	if err != nil {
		fmt.Printf("  cert:      unparseable (%v)\n", err)
		return
	}
	for _, cert := range certs {
		fmt.Printf("  cert:      subject=%q\n", cert.Subject)
		fmt.Printf("             uri_sans=%v\n", cert.URIs)
		fmt.Printf("             not_after=%s (%s from now)\n",
			cert.NotAfter.Format(time.RFC3339), time.Until(cert.NotAfter).Round(time.Second))
		fmt.Printf("             serial=%s\n", cert.SerialNumber)
	}
	fmt.Printf("  key:       %d bytes\n", len(svid.GetX509SvidKey()))
	fmt.Printf("  bundle:    %d bytes\n", len(svid.GetBundle()))
}

// The API may hand back DER or PEM depending on the encoding it chose.
func parseCerts(raw []byte) ([]*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		return x509.ParseCertificates(block.Bytes)
	}
	return x509.ParseCertificates(raw)
}

func writePEM(dir string, svid *pb.X509SVID) error {
	files := []struct {
		name  string
		block string
		data  []byte
	}{
		{"svid.pem", "CERTIFICATE", svid.GetX509Svid()},
		{"key.pem", "PRIVATE KEY", svid.GetX509SvidKey()},
		{"bundle.pem", "CERTIFICATE", svid.GetBundle()},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), encodePEM(f.data, f.block), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// encodePEM emits one PEM block per DER element. The SVID bundle is several
// concatenated certificates, and wrapping it as a single block hides all but
// the first from anything that parses it.
func encodePEM(data []byte, blockType string) []byte {
	if block, _ := pem.Decode(data); block != nil {
		return data
	}
	var out []byte
	for _, der := range splitDER(data) {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})...)
	}
	return out
}

// splitDER walks concatenated DER elements, returning the remainder whole if it
// stops looking like one rather than discarding it.
func splitDER(data []byte) [][]byte {
	var out [][]byte
	for off := 0; off < len(data); {
		n, ok := derElementLen(data[off:])
		if !ok {
			return append(out, data[off:])
		}
		out = append(out, data[off:off+n])
		off += n
	}
	return out
}

func derElementLen(b []byte) (int, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, false
	}
	if b[1] < 0x80 {
		return 2 + int(b[1]), 2+int(b[1]) <= len(b)
	}
	nbytes := int(b[1] & 0x7f)
	if nbytes == 0 || nbytes > 4 || len(b) < 2+nbytes {
		return 0, false
	}
	length := 0
	for _, c := range b[2 : 2+nbytes] {
		length = length<<8 | int(c)
	}
	total := 2 + nbytes + length
	return total, total <= len(b)
}
