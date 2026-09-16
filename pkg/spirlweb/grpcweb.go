// Package spirlweb speaks gRPC-Web to Defakto's serverless SPIFFE Workload API.
//
// The serverless API is four unary RPCs, which is what makes gRPC-Web viable at
// all; the agent APIs are bidi-streaming and can never work over this transport.
package spirlweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

const contentType = "application/grpc-web+proto"

// trailerFlag marks a frame as trailers rather than message data.
const trailerFlag = 0x80

// maxResponseBytes bounds the response read; SVID payloads are a few KB.
const maxResponseBytes = 1 << 20

// StatusError is a non-OK gRPC status. HTTP may still have said 200.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("grpc status %d: %s", e.Code, e.Message)
}

// EncodeRequest returns the framed gRPC-Web request body, so callers can record
// the exact bytes a client must put on the wire.
func EncodeRequest(req proto.Message) ([]byte, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	return frame(0, body), nil
}

// Call performs one unary gRPC-Web call. fullMethod is "pkg.Service/Method".
func Call(ctx context.Context, hc *http.Client, baseURL, fullMethod string, req, resp proto.Message) error {
	body, err := EncodeRequest(req)
	if err != nil {
		return err
	}

	url := strings.TrimSuffix(baseURL, "/") + "/" + fullMethod
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("Accept", contentType)
	httpReq.Header.Set("X-Grpc-Web", "1")

	httpResp, err := hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post %s: %w", url, err)
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(raw)))
	}

	// A trailers-only response carries the status in the HTTP headers instead.
	if s := httpResp.Header.Get("Grpc-Status"); s != "" {
		if err := statusError(s, httpResp.Header.Get("Grpc-Message")); err != nil {
			return err
		}
	}

	data, trailers, err := parseFrames(raw)
	if err != nil {
		return err
	}
	if err := statusError(trailers["grpc-status"], trailers["grpc-message"]); err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("no data frame in response")
	}
	if err := proto.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

func frame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// parseFrames splits a gRPC-Web body into its message bytes and its trailers.
func parseFrames(raw []byte) (data []byte, trailers map[string]string, err error) {
	trailers = map[string]string{}
	for off := 0; off < len(raw); {
		if len(raw)-off < 5 {
			return nil, nil, fmt.Errorf("truncated frame header at byte %d", off)
		}
		flag := raw[off]
		size := int(binary.BigEndian.Uint32(raw[off+1 : off+5]))
		off += 5
		if size < 0 || len(raw)-off < size {
			return nil, nil, fmt.Errorf("frame at byte %d claims %d bytes, %d remain", off-5, size, len(raw)-off)
		}
		payload := raw[off : off+size]
		off += size

		if flag&trailerFlag != 0 {
			for _, line := range strings.Split(string(payload), "\r\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				trailers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
			continue
		}
		if data == nil {
			data = payload
		}
	}
	return data, trailers, nil
}

func statusError(code, message string) error {
	if code == "" {
		return nil
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		return fmt.Errorf("unparseable grpc-status %q", code)
	}
	if n == 0 {
		return nil
	}
	return &StatusError{Code: n, Message: message}
}
