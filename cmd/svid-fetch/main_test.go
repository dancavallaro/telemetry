package main

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derSeq wraps body in a DER SEQUENCE so concatenation can be exercised without
// needing real certificates.
func derSeq(body []byte) []byte {
	if len(body) < 128 {
		return append([]byte{0x30, byte(len(body))}, body...)
	}
	return append([]byte{0x30, 0x82, byte(len(body) >> 8), byte(len(body))}, body...)
}

// The SVID bundle is several concatenated DER certificates; wrapping the whole
// blob in one PEM block silently hides all but the first.
func TestEncodePEMSplitsConcatenatedCerts(t *testing.T) {
	a := derSeq([]byte("first"))
	b := derSeq(make([]byte, 300))

	out := encodePEM(append(append([]byte{}, a...), b...), "CERTIFICATE")

	var blocks []*pem.Block
	rest := out
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		blocks = append(blocks, blk)
	}
	require.Len(t, blocks, 2)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
	assert.Equal(t, a, blocks[0].Bytes)
	assert.Equal(t, b, blocks[1].Bytes)
}

func TestEncodePEMSingleElement(t *testing.T) {
	a := derSeq([]byte("only"))

	blk, rest := pem.Decode(encodePEM(a, "PRIVATE KEY"))

	require.NotNil(t, blk)
	assert.Empty(t, rest)
	assert.Equal(t, "PRIVATE KEY", blk.Type)
	assert.Equal(t, a, blk.Bytes)
}

func TestEncodePEMPassesThroughExistingPEM(t *testing.T) {
	in := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derSeq([]byte("x"))})

	assert.Equal(t, in, encodePEM(in, "CERTIFICATE"))
}

// Trailing bytes that are not a DER SEQUENCE must not be silently dropped.
func TestEncodePEMKeepsUnparseableRemainderInOneBlock(t *testing.T) {
	blk, _ := pem.Decode(encodePEM([]byte{0xff, 0x01, 0x02}, "CERTIFICATE"))

	require.NotNil(t, blk)
	assert.Equal(t, []byte{0xff, 0x01, 0x02}, blk.Bytes)
}
