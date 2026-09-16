package spirlweb

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/dancavallaro/telemetry/pkg/spirlweb/serverlessapi"
)

func TestCallRoundTrip(t *testing.T) {
	var gotPath, gotContentType string
	var gotReq pb.FetchX509SVIDRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		data, _, err := parseFrames(raw)
		require.NoError(t, err)
		require.NoError(t, proto.Unmarshal(data, &gotReq))

		body, err := proto.Marshal(&pb.FetchX509SVIDResponse{
			X509Svids: &pb.X509SVIDResult{
				Svids: []*pb.X509SVID{{SpiffeId: "spiffe://prod.cavallaro.local/skeleton/testdev01"}},
			},
		})
		require.NoError(t, err)

		w.Header().Set("Content-Type", contentType)
		w.Write(frame(0, body))
		w.Write(frame(trailerFlag, []byte("grpc-status:0\r\n")))
	}))
	defer srv.Close()

	var resp pb.FetchX509SVIDResponse
	err := Call(context.Background(), srv.Client(), srv.URL, "com.spirl.serverless.alpha.SpiffeWorkloadAPI/FetchX509SVID",
		&pb.FetchX509SVIDRequest{
			Attestations: []*pb.MethodAttestation{{
				MethodType:    "extension",
				MethodVersion: "1.0",
				Evidence:      []byte(`{"device_id":"testdev01"}`),
			}},
		}, &resp)
	require.NoError(t, err)

	assert.Equal(t, "/com.spirl.serverless.alpha.SpiffeWorkloadAPI/FetchX509SVID", gotPath)
	assert.Equal(t, contentType, gotContentType)
	require.Len(t, gotReq.Attestations, 1)
	assert.Equal(t, "extension", gotReq.Attestations[0].MethodType)
	assert.Equal(t, `{"device_id":"testdev01"}`, string(gotReq.Attestations[0].Evidence))
	require.Len(t, resp.GetX509Svids().GetSvids(), 1)
	assert.Equal(t, "spiffe://prod.cavallaro.local/skeleton/testdev01", resp.GetX509Svids().GetSvids()[0].GetSpiffeId())
}

// The easiest thing to get wrong: HTTP 200 with a failing status in the trailer.
func TestCallTrailerStatusOnHTTP200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(frame(trailerFlag, []byte("grpc-message:unauthenticated\r\ngrpc-status:16\r\n")))
	}))
	defer srv.Close()

	var resp pb.FetchX509SVIDResponse
	err := Call(context.Background(), srv.Client(), srv.URL, "svc/Method", &pb.FetchX509SVIDRequest{}, &resp)

	var statusErr *StatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, 16, statusErr.Code)
	assert.Equal(t, "unauthenticated", statusErr.Message)
}

// Byte-for-byte the trailer frame the live gateway returned when probed.
func TestParseFramesMatchesObservedTrailerFrame(t *testing.T) {
	raw := append([]byte{trailerFlag, 0x00, 0x00, 0x00, 0x2e},
		[]byte("grpc-message:unauthenticated\r\ngrpc-status:16\r\n")...)

	data, trailers, err := parseFrames(raw)
	require.NoError(t, err)
	assert.Nil(t, data)
	assert.Equal(t, "16", trailers["grpc-status"])
	assert.Equal(t, "unauthenticated", trailers["grpc-message"])
}

func TestCallTrailersOnlyInHTTPHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Grpc-Status", "7")
		w.Header().Set("Grpc-Message", "permission denied")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var resp pb.FetchX509SVIDResponse
	err := Call(context.Background(), srv.Client(), srv.URL, "svc/Method", &pb.FetchX509SVIDRequest{}, &resp)

	var statusErr *StatusError
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, 7, statusErr.Code)
}

func TestFrameHeaderIsBigEndian(t *testing.T) {
	f := frame(0, make([]byte, 300))
	assert.Equal(t, byte(0), f[0])
	assert.Equal(t, uint32(300), binary.BigEndian.Uint32(f[1:5]))
	assert.Len(t, f, 305)
}

// Task 8 diffs the ESP32's framed request against this, so the exact bytes
// need to be reachable without making a call.
func TestEncodeRequestIsTheFramedRequestBody(t *testing.T) {
	req := &pb.FetchX509SVIDRequest{
		Attestations: []*pb.MethodAttestation{{
			MethodType:    "extension",
			MethodVersion: "1.0",
			Evidence:      []byte(`{"device_id":"a1b2c3d4e5f6"}`),
		}},
	}

	body, err := EncodeRequest(req)
	require.NoError(t, err)

	marshaled, err := proto.Marshal(req)
	require.NoError(t, err)
	assert.Equal(t, byte(0), body[0], "data frame flag")
	assert.Equal(t, uint32(len(marshaled)), binary.BigEndian.Uint32(body[1:5]))
	assert.Len(t, body, 5+len(marshaled))

	data, _, err := parseFrames(body)
	require.NoError(t, err)
	assert.Equal(t, marshaled, data)
}
