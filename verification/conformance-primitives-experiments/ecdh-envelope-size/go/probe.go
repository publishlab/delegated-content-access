// Go probe. Reads `_shared/fixture.json` inputs, seals and opens the three
// envelope profiles through the standard library, and writes observations as
// JSON on stdout. It reads no expectation and assigns no verdict.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const tagBytes = 16

type keypair struct {
	PrivatePkcs8Hex       string `json:"privatePkcs8Hex"`
	PublicUncompressedHex string `json:"publicUncompressedHex"`
	PublicCompressedHex   string `json:"publicCompressedHex"`
}

type fixture struct {
	Inputs struct {
		Issuer          keypair `json:"issuer"`
		Ephemeral       keypair `json:"ephemeral"`
		EphemeralFresh  keypair `json:"ephemeralFresh"`
		DcaKeyHex       string  `json:"dcaKeyHex"`
		ControlNonceHex string  `json:"controlNonceHex"`
		Bind            struct {
			Value string `json:"value"`
		} `json:"bind"`
		OtherBind struct {
			Value string `json:"value"`
		} `json:"otherBind"`
		Hkdf struct {
			KeyInfoPrefix   string `json:"keyInfoPrefix"`
			NonceInfoPrefix string `json:"nonceInfoPrefix"`
			KeyBytes        int    `json:"keyBytes"`
			NonceBytes      int    `json:"nonceBytes"`
		} `json:"hkdf"`
		OffCurvePoints struct {
			UncompressedHex         string `json:"uncompressedHex"`
			CompressedHex           string `json:"compressedHex"`
			CompressedNonResidueHex string `json:"compressedNonResidueHex"`
		} `json:"offCurvePoints"`
	} `json:"inputs"`
}

// One profile switch, shared by the three shapes: how wide the carried point is,
// and whether the key and nonce come from the fixture or from HKDF.
type shape struct {
	name     string
	pointHex func(keypair) string
	derived  bool
}

var profiles = []shape{
	{"control-109", func(k keypair) string { return k.PublicUncompressedHex }, false},
	{"hkdf-97", func(k keypair) string { return k.PublicUncompressedHex }, true},
	{"hkdf-compressed-65", func(k keypair) string { return k.PublicCompressedHex }, true},
}

var inputs fixture
var compressedImport = "unsupported"
var compressedImportRefusal = ""

func unhex(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	return raw
}

func b64url(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func importPointRaw(point []byte) (*ecdh.PublicKey, error) {
	return ecdh.P256().NewPublicKey(point)
}

// `crypto/ecdh` refuses a 33-byte compressed point, so a compressed point is
// decoded here first and the recovered 65-byte encoding goes through the same
// library import, which validates it.
func importPoint(point []byte) (*ecdh.PublicKey, error) {
	if len(point) == 65 {
		return importPointRaw(point)
	}
	decoded, err := decodeCompressedP256(point)
	if err != nil {
		return nil, err
	}
	return importPointRaw(decoded)
}

// The lane answers the compressed profile as long as the library imports the
// uncompressed point the decoder hands it. If the decoder recovers the wrong
// point, the lane then gives a wrong answer rather than an absent one, and `unsupported` is
// left for a library that refuses the uncompressed form too.
func detectCompressedImport() {
	if _, err := importPointRaw(unhex(inputs.Inputs.Ephemeral.PublicUncompressedHex)); err != nil {
		compressedImportRefusal = err.Error()
		return
	}
	compressedImport = "decoder"
}

func importPrivate(pkcs8Hex string) (*ecdh.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(unhex(pkcs8Hex))
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the PKCS#8 key is not an EC private key")
	}
	return private.ECDH()
}

// The 32-byte fixed-width x-coordinate, or nil when import or agreement fails.
func agree(point []byte, pkcs8Hex string) []byte {
	public, err := importPoint(point)
	if err != nil {
		return nil
	}
	private, err := importPrivate(pkcs8Hex)
	if err != nil {
		return nil
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil
	}
	return shared
}

func derive(secret []byte, info string, length int) []byte {
	out, err := hkdf.Key(sha256.New, secret, nil, info, length)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	return out
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	return aead
}

func gcmSeal(key, nonce, plaintext []byte, aad string) []byte {
	return gcm(key).Seal(nil, nonce, plaintext, []byte(aad))
}

func gcmOpen(key, nonce, carrier []byte, aad string) []byte {
	opened, err := gcm(key).Open(nil, nonce, carrier, []byte(aad))
	if err != nil {
		return nil
	}
	return opened
}

func material(s shape, shared []byte, bind string) ([]byte, []byte) {
	if shared == nil {
		return nil, nil
	}
	if !s.derived {
		return shared, unhex(inputs.Inputs.ControlNonceHex)
	}
	h := inputs.Inputs.Hkdf
	return derive(shared, h.KeyInfoPrefix+bind, h.KeyBytes), derive(shared, h.NonceInfoPrefix+bind, h.NonceBytes)
}

// The publisher side agrees with the issuer public point under the fixed
// ephemeral private key, so every runtime seals the same bytes.
func sealingMaterial(s shape, bind string) ([]byte, []byte) {
	shared := agree(unhex(inputs.Inputs.Issuer.PublicUncompressedHex), inputs.Inputs.Ephemeral.PrivatePkcs8Hex)
	return material(s, shared, bind)
}

func pointBytes(s shape) int {
	if s.name == "hkdf-compressed-65" {
		return 33
	}
	return 65
}

func openEnvelope(s shape, envelope []byte, bind string) []byte {
	width := pointBytes(s)
	if len(envelope) < width {
		return nil
	}
	key, nonce := material(s, agree(envelope[:width], inputs.Inputs.Issuer.PrivatePkcs8Hex), bind)
	if key == nil {
		return nil
	}
	rest := envelope[width:]
	if s.derived {
		return gcmOpen(key, nonce, rest, bind)
	}
	if len(rest) < 12 {
		return nil
	}
	return gcmOpen(key, rest[:12], rest[12:], bind)
}

// The probe reports every negative case as one word. The experiment is looking
// for a released key, so the probe says which of the two happened and
// nothing about the cause.
func releases(s shape, envelope []byte, bind string) string {
	if len(openEnvelope(s, envelope, bind)) > 0 {
		return "key-released"
	}
	return "no-key"
}

func runProfile(s shape) map[string]any {
	bind := inputs.Inputs.Bind.Value
	point := unhex(s.pointHex(inputs.Inputs.Ephemeral))

	if len(point) == 33 && compressedImport == "unsupported" {
		return map[string]any{
			"status": "unsupported",
			"reason": "no compressed-point import through the runtime: " + compressedImportRefusal,
		}
	}

	key, nonce := sealingMaterial(s, bind)
	carrier := gcmSeal(key, nonce, unhex(inputs.Inputs.DcaKeyHex), bind)

	envelope := append([]byte{}, point...)
	if !s.derived {
		envelope = append(envelope, nonce...)
	}
	envelope = append(envelope, carrier...)

	flipped := append([]byte{}, envelope...)
	flipped[len(flipped)-tagBytes-1] ^= 0x01

	badHex := inputs.Inputs.OffCurvePoints.UncompressedHex
	if len(point) == 33 {
		badHex = inputs.Inputs.OffCurvePoints.CompressedHex
	}
	offCurve := append(unhex(badHex), envelope[len(point):]...)

	// A compressed x below p whose curve equation has no square root mod p.
	// Only a 33-byte point carries that case, so the probe reports `n/a` for the wider profiles.
	nonResidue := "n/a"
	if len(point) == 33 {
		carried := unhex(inputs.Inputs.OffCurvePoints.CompressedNonResidueHex)
		nonResidue = releases(s, append(carried, envelope[len(point):]...), bind)
	}

	openedKeyHex := "open-failed"
	if opened := openEnvelope(s, envelope, bind); opened != nil {
		openedKeyHex = hex.EncodeToString(opened)
	}

	return map[string]any{
		"status":            "answered",
		"envelopeHex":       hex.EncodeToString(envelope),
		"derivedKeyHex":     hex.EncodeToString(key),
		"derivedNonceHex":   hex.EncodeToString(nonce),
		"envelopeBase64url": b64url(envelope),
		"decodedBytes":      len(envelope),
		"base64urlChars":    len(b64url(envelope)),
		"pointBytes":        len(point),
		"openedKeyHex":      openedKeyHex,
		"wrongBind":         releases(s, envelope, inputs.Inputs.OtherBind.Value),
		"flippedCiphertext": releases(s, flipped, bind),
		"invalidPoint":      releases(s, offCurve, bind),
		"nonResiduePoint":   nonResidue,
	}
}

func derivedPair(pkcs8Hex, bind string) map[string]string {
	shared := agree(unhex(inputs.Inputs.Issuer.PublicUncompressedHex), pkcs8Hex)
	h := inputs.Inputs.Hkdf
	return map[string]string{
		"keyHex":   hex.EncodeToString(derive(shared, h.KeyInfoPrefix+bind, h.KeyBytes)),
		"nonceHex": hex.EncodeToString(derive(shared, h.NonceInfoPrefix+bind, h.NonceBytes)),
	}
}

func main() {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	source := os.Getenv("DCA_EXPERIMENT_DIR")
	if source == "" {
		source = filepath.Dir(filepath.Dir(self))
	}
	raw, err := os.ReadFile(filepath.Join(source, "_shared", "fixture.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	if err := json.Unmarshal(raw, &inputs); err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}

	detectCompressedImport()
	bind := inputs.Inputs.Bind.Value

	profileObservations := map[string]any{}
	reuse := map[string]any{}
	for _, s := range profiles {
		profileObservations[s.name] = runProfile(s)
	}
	pairs := map[string]any{
		"sameEphemeralSameBind":       derivedPair(inputs.Inputs.Ephemeral.PrivatePkcs8Hex, bind),
		"sameEphemeralSameBindRepeat": derivedPair(inputs.Inputs.Ephemeral.PrivatePkcs8Hex, bind),
		"sameEphemeralOtherBind":      derivedPair(inputs.Inputs.Ephemeral.PrivatePkcs8Hex, inputs.Inputs.OtherBind.Value),
		"freshEphemeralSameBind":      derivedPair(inputs.Inputs.EphemeralFresh.PrivatePkcs8Hex, bind),
	}
	for _, s := range profiles {
		if s.derived {
			reuse[s.name] = pairs
		}
	}

	observations := map[string]any{
		"runtime":               "go",
		"runtimeVersion":        runtime.Version(),
		"cryptoProvider":        "Go standard library, nothing linked",
		"compressedPointImport": compressedImport,
		"profiles":              profileObservations,
		"ephemeralReuse":        reuse,
	}
	out, err := json.MarshalIndent(observations, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
}
