package espattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
)

// TEEFormat marks an envelope around an ESP-TEE attestation token; HMAC
// evidence has no format field.
const TEEFormat = "esp-tee-eat/1"

// teeClientID is the client_id the firmware passes to the TEE ("Defakto").
const teeClientID = 0x0DEFA470

const teeSignAlg = "ecdsa_secp256r1_sha256"

const compressedKeyBytes = 33

type teeEnvelope struct {
	DeviceID string   `json:"device_id"`
	TS       int64    `json:"ts"`
	Nonce    string   `json:"nonce"`
	Token    teeToken `json:"token"`
}

// The signature covers the exact bytes of header, eat and public_key, so they
// stay raw until it has been checked.
type teeToken struct {
	Header    json.RawMessage `json:"header"`
	EAT       json.RawMessage `json:"eat"`
	PublicKey json.RawMessage `json:"public_key"`
	Sign      struct {
		R string `json:"r"`
		S string `json:"s"`
	} `json:"sign"`
}

// The TEE prints nonce and client_id as signed 32-bit decimals.
type teeEAT struct {
	Nonce    int64 `json:"nonce"`
	ClientID int64 `json:"client_id"`
	SWClaims struct {
		TEE        teeImageClaims `json:"tee"`
		App        teeImageClaims `json:"app"`
		Bootloader teeImageClaims `json:"bootloader"`
	} `json:"sw_claims"`
}

type teeImageClaims struct {
	Ver        string `json:"ver"`
	IDFVer     string `json:"idf_ver"`
	SecureVer  int64  `json:"secure_ver"`
	PartDigest struct {
		CalcDigest   string `json:"calc_digest"`
		SignVerified bool   `json:"sign_verified"`
	} `json:"part_digest"`
}

// ParseTEEPubKey decodes a compressed SEC1 P-256 public key from hex.
func ParseTEEPubKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("TEE public key is not hex: %w", err)
	}
	if len(key) != compressedKeyBytes {
		return nil, fmt.Errorf("TEE public key is %d bytes, want %d (compressed P-256)", len(key), compressedKeyBytes)
	}
	if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), key); x == nil {
		return nil, fmt.Errorf("TEE public key is not a compressed P-256 point")
	}
	return key, nil
}

// teeNonce is the 32-bit nonce the device asked the TEE to sign: a digest of
// the HMAC signing string, so both anchors bind the same device_id|ts|nonce.
func teeNonce(deviceID string, ts int64, nonce string) uint32 {
	digest := sha256.Sum256([]byte(signingString(deviceID, ts, nonce)))
	return binary.BigEndian.Uint32(digest[:4])
}

// verify checks the token against the enrolled key and the envelope it came
// in, returning the attested claims.
func (env teeEnvelope) verify(enrolledKey []byte) (teeEAT, error) {
	var eat teeEAT
	tok := env.Token

	var header struct {
		SignAlg string `json:"sign_alg"`
	}
	if err := json.Unmarshal(tok.Header, &header); err != nil {
		return eat, fmt.Errorf("parsing header: %w", err)
	}
	if header.SignAlg != teeSignAlg {
		return eat, fmt.Errorf("sign_alg %q, want %q", header.SignAlg, teeSignAlg)
	}

	var publicKey struct {
		Compressed string `json:"compressed"`
	}
	if err := json.Unmarshal(tok.PublicKey, &publicKey); err != nil {
		return eat, fmt.Errorf("parsing public_key: %w", err)
	}
	key, err := hex.DecodeString(publicKey.Compressed)
	if err != nil || !bytes.Equal(key, enrolledKey) {
		return eat, fmt.Errorf("token key %q is not the enrolled key", publicKey.Compressed)
	}

	if !verifyTEESignature(enrolledKey, tok) {
		return eat, fmt.Errorf("signature mismatch")
	}

	if err := json.Unmarshal(tok.EAT, &eat); err != nil {
		return eat, fmt.Errorf("parsing eat: %w", err)
	}
	if want := teeNonce(env.DeviceID, env.TS, env.Nonce); uint32(eat.Nonce) != want {
		return eat, fmt.Errorf("eat.nonce %#08x is not bound to the envelope (want %#08x)", uint32(eat.Nonce), want)
	}
	if uint32(eat.ClientID) != teeClientID {
		return eat, fmt.Errorf("eat.client_id %#08x, want %#08x", uint32(eat.ClientID), teeClientID)
	}
	return eat, nil
}

func verifyTEESignature(compressedKey []byte, tok teeToken) bool {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressedKey)
	if x == nil {
		return false
	}
	r, okR := new(big.Int).SetString(tok.Sign.R, 16)
	s, okS := new(big.Int).SetString(tok.Sign.S, 16)
	if !okR || !okS {
		return false
	}

	h := sha256.New()
	h.Write(tok.Header)
	h.Write(tok.EAT)
	h.Write(tok.PublicKey)
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h.Sum(nil), r, s)
}

func (eat teeEAT) attributes(deviceID string) attestResponse {
	sw := eat.SWClaims
	secureBoot := sw.TEE.PartDigest.SignVerified &&
		sw.App.PartDigest.SignVerified &&
		sw.Bootloader.PartDigest.SignVerified
	return attestResponse{
		"device_id":          deviceID,
		"anchor":             "tee",
		"app_version":        sw.App.Ver,
		"app_digest":         sw.App.PartDigest.CalcDigest,
		"app_secure_version": strconv.FormatInt(sw.App.SecureVer, 10),
		"tee_version":        sw.TEE.Ver,
		"tee_digest":         sw.TEE.PartDigest.CalcDigest,
		"bootloader_digest":  sw.Bootloader.PartDigest.CalcDigest,
		"idf_version":        sw.App.IDFVer,
		"secure_boot":        strconv.FormatBool(secureBoot),
	}
}
