// The Go bridge answers the contract's seven operations and says nothing about
// whether its own answers are right.
//
// The bridge reads a single
// `dca-operation-bridge-v1` JSON document from stdin, computes one observation
// per request, writes a single JSON document to stdout and exits 0. Human
// diagnostics go to stderr; nothing reads a result out of stderr, so a bridge
// may write anything there.
//
// Every operation here is one stock library call: decode a strict base64url
// field, derive octets with HKDF-SHA-256, open and seal an AES-GCM carrier,
// agree a P-256 secret, encode a P-256 public point, and open an RSA-OAEP
// ciphertext. The bridge joins nothing, slices nothing and derives nothing on
// another layer's behalf. It takes octets, keys and lengths, and it answers
// octets.
//
// The Go bridge has no record of what any observation is supposed to be. There is
// no expected value here, no comparison, no `held`, `disagreed` or `incomplete`
// word, no pass count and no total. It never opens the case corpus, and the
// request it is handed carries no `expected` and no `class` for it to peek at.
// Nobody has tested a bridge that can read the answer, and if a bridge reported
// its own verdict, the harness would have a second opinion to reconcile.
//
// The library calls live in `conformance-primitives/go/v1/internal/primitives`,
// which this package imports: JWK import, the AES-GCM carrier, HKDF and RSA
// private-key import. Nothing there reads the wire protocol or a refusal code,
// so the code in this file decides what a failure means for its own answer.
//
// The bridge reports a defined refusal as an answer. `invalid_base64url`,
// `authentication_failed` and `unseal_failed` are observations inside an exit-0
// result, because refusing correctly is one of the behaviours under test. A
// request the bridge cannot serve at all, an unparseable batch, an unknown
// operation or an input shape outside the contract, takes the other path: the
// bridge exits nonzero with a stderr line and writes no partial results, and the
// runner reads that as a run that could not be completed. In Go the two
// paths map onto return values. The bridge returns a refusal as a value beside a nil
// error, and returns everything it cannot serve as an error.
//
// `open-aes-gcm` folds a wrong key, a wrong nonce, other additional data and a
// flipped octet into one `authentication_failed`, because the AEAD tag check fails the
// same way for each of those. `open-rsa-oaep` folds the same set of causes
// into `unseal_failed`, the one failure OAEP itself reports. The bridge reads both refusals off
// Go's own AEAD and OAEP errors, never off which step ran. A seal, a derivation
// and a point encoding define no refusal, so every failure in them is a request
// this bridge cannot serve.
//
// The bridge checks every shape it reads, and each one is closed. The envelope
// carries `protocol` and `requests`, a request row carries `id`, `op` and
// `input`, and an input carries exactly the members its operation names. The
// bridge reads every object as a map of raw members and compares its member set
// by name, because `encoding/json` unmarshalling into a struct drops members
// nobody declared and matches the declared ones without regard to case:
// `{"Value":"..."}` would fill a `value` field, and a member the contract does
// not name would pass unseen.
//
// The Go bridge reads the batch with Go's own JSON parser and nothing else.
// This file runs no token scanner. `encoding/json` keeps the last spelling of a
// repeated member and reports no error, and this bridge does not check for repeats: Node
// writes the octets on stdin and never repeats a member, so a bridge defending
// against one would be defending against its own harness, once per language.
//
// Standard library only. Verified on go1.27.0 linux/amd64.
//
// Run (the runner builds it first and then does this; by hand it is the same):
//
//	printf '%s\n' '<batch json>' | ./bridge
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"conformance-primitives/go/v1/internal/primitives"
)

const batchProtocol = "dca-operation-bridge-v1"

// The widths AES-GCM fixes: a 16-octet key selects AES-128-GCM and a 32-octet
// key AES-256-GCM, the nonce is 12 octets, and the tag is the last 16 octets of
// the carrier.
const (
	aes128KeyBytes = 16
	aes256KeyBytes = 32
	nonceBytes     = 12
)

// How many octets one HKDF-SHA-256 expansion answers: at least one, and at most
// the 255 hash blocks RFC 5869 section 2.3 allows, 8160 octets.
const (
	hkdfMinOctets = 1
	hkdfMaxOctets = 255 * 32
)

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

// One process, from the octets on stdin to the exit status.
//
// The bridge builds the result whole before an octet of it reaches stdout, so a
// batch it cannot finish leaves stdout empty rather than half a document. The
// recover catches a panic for the same reason a refusal is returned as a value: the
// runner would read a panic as a bridge that died, and this one exits 1 with the
// reason on stderr instead.
func run(in io.Reader, out io.Writer, diag io.Writer) (status int) {
	defer func() {
		if panicked := recover(); panicked != nil {
			fmt.Fprintf(diag, "bridge: %v\n", panicked)
			status = 1
		}
	}()

	raw, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintf(diag, "bridge: stdin could not be read: %v\n", err)
		return 1
	}

	results, err := answerBatch(raw, diag)
	if err != nil {
		fmt.Fprintf(diag, "bridge: %v\n", err)
		return 1
	}

	encoded, err := encodeBatch(results)
	if err != nil {
		fmt.Fprintf(diag, "bridge: the answers could not be encoded: %v\n", err)
		return 1
	}
	if _, err := out.Write(encoded); err != nil {
		fmt.Fprintf(diag, "bridge: stdout could not be written: %v\n", err)
		return 1
	}
	return 0
}

type result struct {
	ID          string      `json:"id"`
	Op          string      `json:"op"`
	Observation observation `json:"observation"`
}

// An observation carries exactly one of its operation's defined member sets.
// The pointers hold that on the wire: `omitempty` drops a nil pointer and keeps
// a pointer to the empty string, so a zero-octet decode answers
// `{"bytesHex":""}` rather than an empty object.
type observation struct {
	BytesHex              *string `json:"bytesHex,omitempty"`
	OkmBase64url          *string `json:"okmBase64url,omitempty"`
	PlaintextBase64url    *string `json:"plaintextBase64url,omitempty"`
	CiphertextBase64url   *string `json:"ciphertextBase64url,omitempty"`
	SharedSecretBase64url *string `json:"sharedSecretBase64url,omitempty"`
	PointBase64url        *string `json:"pointBase64url,omitempty"`
	Refused               *string `json:"refused,omitempty"`
}

func encodeBatch(results []result) ([]byte, error) {
	envelope := struct {
		Protocol string   `json:"protocol"`
		Results  []result `json:"results"`
	}{Protocol: batchProtocol, Results: results}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// The observation values are the behaviour under test, and `<`, `>` and `&`
	// are ordinary octets in them. Go escapes those three by default, which
	// would spell an answer differently than every other bridge spells it.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// The request envelope, read strictly, and one result per request in request order.
//
// Order is irrelevant to the runner, which keys results by the (id, op) pair, so
// the bridge keeps request order only because it makes a hand-read batch easy to
// follow.
func answerBatch(raw []byte, diag io.Writer) ([]result, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var top json.RawMessage
	if err := decoder.Decode(&top); err != nil {
		return nil, fmt.Errorf("the batch on stdin is not readable JSON: %w", err)
	}
	// Stdin carries one document. A second value after the first means the
	// sender is not following this protocol.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the batch on stdin carries more than one JSON value")
	}

	batch, err := closedMembers(top, []string{"protocol", "requests"}, "the batch")
	if err != nil {
		return nil, err
	}
	protocol, err := memberString(batch, "protocol", "the batch")
	if err != nil {
		return nil, err
	}
	if protocol != batchProtocol {
		return nil, fmt.Errorf("the batch names protocol %q, which this bridge does not speak", protocol)
	}

	var requests []json.RawMessage
	if err := json.Unmarshal(batch["requests"], &requests); err != nil {
		return nil, fmt.Errorf("the batch carries no requests array: %w", err)
	}

	results := make([]result, 0, len(requests))
	for position, raw := range requests {
		one, err := answerRequest(raw, position, diag)
		if err != nil {
			return nil, err
		}
		results = append(results, one)
	}
	return results, nil
}

// One request row, read strictly, and the one observation it asks for.
func answerRequest(raw json.RawMessage, position int, diag io.Writer) (result, error) {
	where := fmt.Sprintf("request %d", position)
	entry, err := closedMembers(raw, []string{"id", "op", "input"}, where)
	if err != nil {
		return result{}, err
	}
	id, err := memberString(entry, "id", where)
	if err != nil {
		return result{}, err
	}
	if id == "" {
		return result{}, fmt.Errorf("%s carries an empty id", where)
	}
	op, err := memberString(entry, "op", fmt.Sprintf("request %s", id))
	if err != nil {
		return result{}, err
	}

	seen, err := observe(op, entry["input"], id, diag)
	if err != nil {
		return result{}, err
	}
	return result{ID: id, Op: op, Observation: seen}, nil
}

// One observation for one request, or an error if the operation is not one this bridge implements.
func observe(op string, input json.RawMessage, id string, diag io.Writer) (observation, error) {
	switch op {
	case "decode-base64url":
		return observeDecodeBase64url(input, id, diag)
	case "hkdf-sha256":
		return observeHkdfSha256(input, id)
	case "open-aes-gcm":
		return observeOpenAesGcm(input, id, diag)
	case "seal-aes-gcm":
		return observeSealAesGcm(input, id)
	case "ecdh-p256":
		return observeEcdhP256(input, id)
	case "p256-point":
		return observeP256Point(input, id)
	case "open-rsa-oaep":
		return observeOpenRsaOaep(input, id, diag)
	default:
		return observation{}, fmt.Errorf("request %s names operation %q, which this bridge does not implement", id, op)
	}
}

// The strict field spelling: RFC 4648 section 5 alphabet, no padding, a length
// that encodes a whole octet count, and zero unused trailing bits.
//
// Which of those rules fired goes to stderr. The observation carries the one
// closed code, because the contract has one.
func observeDecodeBase64url(input json.RawMessage, id string, diag io.Writer) (observation, error) {
	members, err := closedMembers(input, []string{"value"}, fmt.Sprintf("the input of request %s", id))
	if err != nil {
		return observation{}, err
	}
	value, err := memberString(members, "value", fmt.Sprintf("the input of request %s", id))
	if err != nil {
		return observation{}, err
	}

	decoded, why := decodeStrictBase64url(value)
	if why != nil {
		fmt.Fprintf(diag, "bridge: %s refused %q: %v.\n", id, value, why)
		return refusal("invalid_base64url"), nil
	}
	return observation{BytesHex: stringPointer(hex.EncodeToString(decoded))}, nil
}

// One HKDF-SHA-256 invocation (RFC 5869) with an empty salt, over the decoded
// ikm and info octets, answering `length` octets.
//
// The caller hands over octets and a width. `info` carries 0x00 and octets
// above 0x7f, and the bridge passes it from the strict base64url reader to the
// derivation as octets.
//
// The operation defines no refusal. An input that does not decode, or a length
// outside the bounds above, makes a batch this bridge cannot serve.
func observeHkdfSha256(input json.RawMessage, id string) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(input, []string{"ikmBase64url", "infoBase64url", "length"}, where)
	if err != nil {
		return observation{}, err
	}
	ikm, err := carrierBytes(members, "ikmBase64url", id)
	if err != nil {
		return observation{}, err
	}
	info, err := carrierBytes(members, "infoBase64url", id)
	if err != nil {
		return observation{}, err
	}
	length, err := memberLength(members, "length", where)
	if err != nil {
		return observation{}, err
	}
	okm, err := primitives.HKDF(ikm, info, length)
	if err != nil {
		return observation{}, fmt.Errorf("request %s asks for %d octets, and this runtime's HKDF-SHA-256 would not answer: %w", id, length, err)
	}
	return observation{OkmBase64url: stringPointer(primitives.B64uEnc(okm))}, nil
}

// One output width, present and a JSON integer inside the bounds above, or a
// request this bridge cannot serve.
//
// json.Number keeps the literal the sender wrote, and Int64 reads it as an
// integer, so this reader refuses 16.0 and 1.6e1 rather than rounding either
// into a width nobody asked for.
func memberLength(object map[string]json.RawMessage, member string, what string) (int, error) {
	raw, ok := object[member]
	if !ok {
		return 0, fmt.Errorf("%s carries no %s", what, member)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, fmt.Errorf("%s carries a non-numeric %s: %w", what, member, err)
	}
	value, err := number.Int64()
	if err != nil {
		return 0, fmt.Errorf("%s carries %s as %s, and it carries a whole number: %w", what, member, number.String(), err)
	}
	if value < hkdfMinOctets || value > hkdfMaxOctets {
		return 0, fmt.Errorf("%s carries %s as %d, and one HKDF-SHA-256 expansion answers %d through %d octets", what, member, value, hkdfMinOctets, hkdfMaxOctets)
	}
	return int(value), nil
}

// AES-GCM over one `ciphertext || tag` carrier, which is how the contract
// carries it. The key's width picks the cipher: 16 octets for AES-128-GCM and
// 32 for AES-256-GCM.
//
// A key or a nonce of another width is a request this bridge cannot serve,
// named as such rather than cut to size: a bridge that quietly truncates a
// 33-octet key answers about a key nobody sent. A tag that does not verify produces
// the refusal, whatever the cause, and a carrier holding fewer octets than a
// tag is one such cause, so `Open` reports it the same way and nothing here
// crashes on a short buffer.
func observeOpenAesGcm(input json.RawMessage, id string, diag io.Writer) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(
		input,
		[]string{"keyBase64url", "nonceBase64url", "ciphertextBase64url", "aadBase64url"},
		where,
	)
	if err != nil {
		return observation{}, err
	}

	key, nonce, aad, err := aesGcmKeyNonceAad(members, id)
	if err != nil {
		return observation{}, err
	}
	carrier, err := carrierBytes(members, "ciphertextBase64url", id)
	if err != nil {
		return observation{}, err
	}

	plaintext := primitives.GCMOpen(key, nonce, carrier, aad)
	if plaintext == nil {
		fmt.Fprintf(diag, "bridge: %s did not authenticate.\n", id)
		return refusal("authentication_failed"), nil
	}
	return observation{PlaintextBase64url: stringPointer(primitives.B64uEnc(plaintext))}, nil
}

// The same carrier, sealed. The nonce arrives as an input, so a seal has one
// determined answer, and the 16-octet tag goes on the end of the ciphertext.
//
// The operation defines no refusal: every failure here is a request this bridge
// cannot serve.
func observeSealAesGcm(input json.RawMessage, id string) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(
		input,
		[]string{"keyBase64url", "nonceBase64url", "plaintextBase64url", "aadBase64url"},
		where,
	)
	if err != nil {
		return observation{}, err
	}

	key, nonce, aad, err := aesGcmKeyNonceAad(members, id)
	if err != nil {
		return observation{}, err
	}
	plaintext, err := carrierBytes(members, "plaintextBase64url", id)
	if err != nil {
		return observation{}, err
	}

	ciphertext := primitives.GCMSeal(key, nonce, plaintext, aad)
	if ciphertext == nil {
		return observation{}, fmt.Errorf("request %s: this runtime's AES-GCM would not seal", id)
	}
	return observation{CiphertextBase64url: stringPointer(primitives.B64uEnc(ciphertext))}, nil
}

// The three members the two AES-GCM operations share, read and width-checked
// once. `aadBase64url` may be the empty string, which decodes to additional
// data of zero octets, and Go's AEAD treats a zero-length slice and a nil the
// same way.
func aesGcmKeyNonceAad(members map[string]json.RawMessage, id string) (key, nonce, aad []byte, err error) {
	key, err = carrierBytes(members, "keyBase64url", id)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(key) != aes128KeyBytes && len(key) != aes256KeyBytes {
		return nil, nil, nil, fmt.Errorf(
			"request %s carries a %d-octet key, and AES-GCM takes %d for AES-128 or %d for AES-256",
			id, len(key), aes128KeyBytes, aes256KeyBytes,
		)
	}
	nonce, err = carrierBytes(members, "nonceBase64url", id)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(nonce) != nonceBytes {
		return nil, nil, nil, fmt.Errorf("request %s carries a %d-octet nonce, and this carrier takes exactly %d", id, len(nonce), nonceBytes)
	}
	aad, err = carrierBytes(members, "aadBase64url", id)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, nonce, aad, nil
}

// One ECDH agreement over P-256: import the peer's 65-octet uncompressed SEC 1
// point with Go's own crypto/ecdh routines, import the private JWK by its `d`
// scalar, and agree once.
//
// crypto/ecdh answers the agreed x-coordinate at the P-256 field width, 32
// octets, keeping a leading zero octet where a big-integer API would drop one.
// The bridge applies no KDF to it.
//
// The operation defines no refusal. A peer value this runtime cannot import is
// a request this bridge cannot serve.
func observeEcdhP256(input json.RawMessage, id string) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(input, []string{"privateKeyJwk", "peerPointBase64url"}, where)
	if err != nil {
		return observation{}, err
	}

	privateJwk, err := jwkMember(members, "privateKeyJwk", id)
	if err != nil {
		return observation{}, err
	}
	private, err := primitives.ECDHPrivateFromJWK(privateJwk)
	if err != nil {
		return observation{}, fmt.Errorf("request %s carries a privateKeyJwk this bridge cannot import: %w", id, err)
	}

	peerPoint, err := carrierBytes(members, "peerPointBase64url", id)
	if err != nil {
		return observation{}, err
	}
	peer, err := primitives.ECDHCurve.NewPublicKey(peerPoint)
	if err != nil {
		return observation{}, fmt.Errorf("request %s carries a peerPointBase64url this runtime cannot import: %w", id, err)
	}

	shared, err := private.ECDH(peer)
	if err != nil {
		return observation{}, fmt.Errorf("request %s: this runtime would not agree over P-256: %w", id, err)
	}
	return observation{SharedSecretBase64url: stringPointer(primitives.B64uEnc(shared))}, nil
}

// One public JWK written as the 65-octet uncompressed SEC 1 point: 0x04, then
// `x`, then `y`, each coordinate at its full 32-octet width. crypto/ecdh's own
// importer reads the point and its Bytes writes it back, so the widths follow that
// package's rule rather than this file's.
//
// The operation defines no refusal.
func observeP256Point(input json.RawMessage, id string) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(input, []string{"publicKeyJwk"}, where)
	if err != nil {
		return observation{}, err
	}

	publicJwk, err := jwkMember(members, "publicKeyJwk", id)
	if err != nil {
		return observation{}, err
	}
	point := primitives.PointFromJWK(publicJwk)
	if point == nil {
		return observation{}, fmt.Errorf("request %s carries a publicKeyJwk with a coordinate wider than the 32 octets P-256 carries", id)
	}
	public, err := primitives.ECDHCurve.NewPublicKey(point)
	if err != nil {
		return observation{}, fmt.Errorf("request %s carries a publicKeyJwk this runtime cannot import: %w", id, err)
	}
	return observation{PointBase64url: stringPointer(primitives.B64uEnc(public.Bytes()))}, nil
}

// One recorded RSA-OAEP ciphertext over SHA-256, MGF1 with the same hash and no
// label, opened to the whole plaintext with one crypto/rsa call. The corpus
// decides what the plaintext holds, so this operation hands back every octet of
// it.
//
// A wrong private key, a ciphertext that is not one modulus wide and a flipped
// octet all produce one `unseal_failed`, the one failure OAEP itself reports, and this operation
// does not try to tell them apart.
func observeOpenRsaOaep(input json.RawMessage, id string, diag io.Writer) (observation, error) {
	where := fmt.Sprintf("the input of request %s", id)
	members, err := closedMembers(input, []string{"ciphertextBase64url", "privateKeyJwk"}, where)
	if err != nil {
		return observation{}, err
	}

	privateJwk, err := rsaJwkMember(members, "privateKeyJwk", id)
	if err != nil {
		return observation{}, err
	}
	private, err := primitives.RSAPrivateFromJWK(privateJwk)
	if err != nil {
		return observation{}, fmt.Errorf("request %s carries a privateKeyJwk this bridge cannot import: %w", id, err)
	}

	carrier, err := carrierBytes(members, "ciphertextBase64url", id)
	if err != nil {
		return observation{}, err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, private, carrier, nil)
	if err != nil {
		fmt.Fprintf(diag, "bridge: %s did not open: %v.\n", id, err)
		return refusal("unseal_failed"), nil
	}
	return observation{PlaintextBase64url: stringPointer(primitives.B64uEnc(plaintext))}, nil
}

// jwkMember reads one input member as an EC JWK, exactly as the corpus records
// it: one JSON object passed through unchanged to the primitives package. A
// member missing or not an object is a request this bridge cannot serve;
// whether its fields form a key this runtime can use is for the caller's import
// call to say.
func jwkMember(object map[string]json.RawMessage, member string, id string) (primitives.JWK, error) {
	raw, ok := object[member]
	if !ok {
		return primitives.JWK{}, fmt.Errorf("the input of request %s carries no %s", id, member)
	}
	var jwk primitives.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return primitives.JWK{}, fmt.Errorf("request %s carries a %s that is not a JSON object: %w", id, member, err)
	}
	return jwk, nil
}

// rsaJwkMember is jwkMember for the RSA private key open-rsa-oaep takes.
func rsaJwkMember(object map[string]json.RawMessage, member string, id string) (primitives.RSAJWK, error) {
	raw, ok := object[member]
	if !ok {
		return primitives.RSAJWK{}, fmt.Errorf("the input of request %s carries no %s", id, member)
	}
	var jwk primitives.RSAJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return primitives.RSAJWK{}, fmt.Errorf("request %s carries a %s that is not a JSON object: %w", id, member, err)
	}
	return jwk, nil
}

// One JSON object holding exactly the named members, or a request this bridge
// cannot serve.
//
// The contract calls the envelope, the request row and every input closed, and a
// closed shape goes unenforced until something checks it. A
// member outside the set means the sender is writing a protocol this bridge has
// not agreed to, and a missing one means the sender left out something the
// operation is defined by.
func closedMembers(raw json.RawMessage, members []string, what string) (map[string]json.RawMessage, error) {
	object, err := asObject(raw, what)
	if err != nil {
		return nil, err
	}

	named := make(map[string]bool, len(members))
	for _, member := range members {
		named[member] = true
	}
	unknown := make([]string, 0)
	for member := range object {
		if !named[member] {
			unknown = append(unknown, member)
		}
	}
	absent := make([]string, 0)
	for _, member := range members {
		if _, ok := object[member]; !ok {
			absent = append(absent, member)
		}
	}

	if len(unknown) > 0 || len(absent) > 0 {
		return nil, fmt.Errorf("%s carries {%s}, and it carries {%s} exactly", what, strings.Join(memberNames(object), ", "), strings.Join(members, ", "))
	}
	return object, nil
}

// One JSON object as its raw members, keyed by their exact spelling.
func asObject(raw json.RawMessage, what string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is not there", what)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", what, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s is null, and it is a JSON object", what)
	}
	return object, nil
}

// The member names an object carries, in a fixed order so two runs report the
// same shape the same way.
func memberNames(object map[string]json.RawMessage) []string {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// One member that must be present and a string, or a request this bridge cannot serve.
func memberString(object map[string]json.RawMessage, member string, what string) (string, error) {
	raw, ok := object[member]
	if !ok {
		return "", fmt.Errorf("%s carries no %s", what, member)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s carries a non-string %s: %w", what, member, err)
	}
	return value, nil
}

// One base64url input member decoded to raw octets. Every carrier literal the
// harness sends is canonical, so a spelling that fails the strict rule here makes a
// batch this bridge cannot serve rather than a request it answers.
func carrierBytes(object map[string]json.RawMessage, member string, id string) ([]byte, error) {
	value, err := memberString(object, member, fmt.Sprintf("the input of request %s", id))
	if err != nil {
		return nil, err
	}
	decoded, why := decodeStrictBase64url(value)
	if why != nil {
		return nil, fmt.Errorf("request %s carries a %s this bridge cannot decode: %w", id, member, why)
	}
	return decoded, nil
}

// Canonical unpadded base64url to octets, or the reason it is not canonical.
//
// The four rules are spelled out because the standard decoder holds two of them
// and not the other two. `RawURLEncoding` refuses `+`, `/` and `=` and refuses a
// length of 1 modulo 4, and it accepts unused trailing bits: `3q2-7x` decodes to
// the same three octets as `3q2-7w`. `Strict()` refuses those bits, and the
// decode-and-re-encode comparison below refuses them as well while saying which
// spelling the value would have had, so the reason on stderr names the value the
// sender could have written.
func decodeStrictBase64url(value string) ([]byte, error) {
	for position, character := range []byte(value) {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '_':
		default:
			return nil, fmt.Errorf("octet %d is %q, outside the base64url alphabet, which is where padding is refused", position, string(character))
		}
	}
	if len(value)%4 == 1 {
		return nil, fmt.Errorf("a length of %d encodes no whole octet count", len(value))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("octets the base64url decoder would not read: %w", err)
	}
	if spelling := base64.RawURLEncoding.EncodeToString(decoded); spelling != value {
		return nil, fmt.Errorf("unused trailing bits: those octets are spelled %q", spelling)
	}
	return decoded, nil
}

func refusal(code string) observation {
	return observation{Refused: stringPointer(code)}
}

func stringPointer(value string) *string {
	return &value
}
