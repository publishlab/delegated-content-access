//! The RustCrypto bridge answers the contract's seven operations and says
//! nothing about whether its own answers are right.
//!
//! The bridge reads a single `dca-operation-bridge-v1` JSON document from
//! stdin, computes one observation per request, writes a single JSON document
//! to stdout and exits 0. Human diagnostics go to stderr; nothing reads a
//! result out of stderr, so a bridge may write anything there.
//!
//! Every operation here is one library call: decode a strict base64url field,
//! derive octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a
//! P-256 secret, encode a P-256 public point, and open an RSA-OAEP ciphertext.
//! The bridge joins nothing, slices nothing and derives nothing on another
//! layer's behalf. It takes octets, keys and lengths, and it answers octets.
//!
//! The bridge has no record of what any observation is supposed to be. There
//! is no expected value here, no comparison, no verdict word, no pass count
//! and no total. It never opens the case corpus, and the request it is handed
//! carries no `expected` for it to peek at.
//!
//! The library calls live in the `primitives` library beside this binary,
//! `v1/primitives/lib.rs`. Nothing there reads the wire protocol or a refusal
//! code, so the code in this file decides what a failure means for its own
//! answer.
//!
//! A defined refusal is an answer. `invalid_base64url`,
//! `authentication_failed` and `unseal_failed` are observations inside an
//! exit-0 result. A request the bridge cannot serve at all, an unparseable
//! batch, an unknown operation or an input shape outside the contract, takes
//! the other path: the bridge exits 1 with a stderr line and writes nothing on
//! stdout. In Rust the two paths are the two arms of a `Result`: a refusal is
//! an `Ok` observation, and everything the bridge cannot serve is an `Err`.
//!
//! Every shape the bridge reads is closed. The envelope carries `protocol` and
//! `requests`, a request row carries `id`, `op` and `input`, and an input
//! carries exactly the members its operation names. `serde_json` reads each
//! object into a map, and the bridge compares the map's member names with the
//! set the contract names, so a member the contract does not name, or one
//! spelled in another case, is refused rather than passed over.
//!
//! `serde_json` is the only JSON parser here. It keeps the last spelling of a
//! repeated member and reports no error, and this bridge does not check for
//! repeats: the harness writes the octets on stdin and never repeats a member.
//!
//! Run (the runner builds it first and then does this; by hand it is the same):
//!
//! ```text
//! printf '%s\n' '<batch json>' | ./target/release/bridge
//! ```

use std::io::{Read, Write};
use std::panic;
use std::process::ExitCode;

use serde_json::{Map, Value};

use primitives::{
    decode_strict_base64url, encode_base64url, gcm_open, gcm_seal, hkdf_sha256, p256_ecdh,
    p256_point_from_coordinates, p256_public_key, p256_secret_key, p256_uncompressed_point,
    rsa_oaep_sha256_open, rsa_private_key,
};

const BATCH_PROTOCOL: &str = "dca-operation-bridge-v1";

/// How many octets one HKDF-SHA-256 expansion answers: at least one, and at
/// most the 255 hash blocks RFC 5869 section 2.3 allows, 8160 octets.
const HKDF_MIN_OCTETS: u64 = 1;
const HKDF_MAX_OCTETS: u64 = 255 * 32;

/// A request this bridge cannot serve, with the reason for stderr.
type Fault = String;

fn main() -> ExitCode {
    // The default hook would print the panic and the bridge would exit 101.
    // The runner reads any nonzero exit the same way, and a panic caught here
    // exits 1 with its reason on stderr and nothing on stdout, like every other
    // request this bridge cannot serve.
    panic::set_hook(Box::new(|info| eprintln!("bridge: {info}")));
    match panic::catch_unwind(run) {
        Ok(status) => status,
        Err(_) => ExitCode::from(1),
    }
}

/// One process, from the octets on stdin to the exit status.
///
/// The bridge builds the result whole before an octet of it reaches stdout,
/// so a batch it cannot finish leaves stdout empty rather than half a
/// document.
fn run() -> ExitCode {
    let mut raw = Vec::new();
    if let Err(error) = std::io::stdin().read_to_end(&mut raw) {
        eprintln!("bridge: stdin could not be read: {error}");
        return ExitCode::from(1);
    }

    let results = match answer_batch(&raw) {
        Ok(results) => results,
        Err(fault) => {
            eprintln!("bridge: {fault}");
            return ExitCode::from(1);
        }
    };

    let mut envelope = Map::new();
    envelope.insert("protocol".into(), Value::from(BATCH_PROTOCOL));
    envelope.insert("results".into(), Value::Array(results));
    let mut encoded = match serde_json::to_vec(&Value::Object(envelope)) {
        Ok(encoded) => encoded,
        Err(error) => {
            eprintln!("bridge: the answers could not be encoded: {error}");
            return ExitCode::from(1);
        }
    };
    encoded.push(b'\n');

    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(&encoded).and_then(|()| stdout.flush()) {
        eprintln!("bridge: stdout could not be written: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The request envelope, read strictly, and one result per request in request
/// order. The runner keys results by the `(id, op)` pair, so the order only
/// makes a hand-read batch easy to follow.
///
/// `serde_json::from_slice` refuses trailing octets other than whitespace, so a
/// second JSON value after the first is refused here as well.
fn answer_batch(raw: &[u8]) -> Result<Vec<Value>, Fault> {
    let top: Value = serde_json::from_slice(raw)
        .map_err(|error| format!("the batch on stdin is not one readable JSON value: {error}"))?;
    let batch = closed_members(&top, &["protocol", "requests"], "the batch")?;
    let protocol = member_str(batch, "protocol", "the batch")?;
    if protocol != BATCH_PROTOCOL {
        return Err(format!("the batch names protocol {protocol:?}, which this bridge does not speak"));
    }
    let requests = batch["requests"]
        .as_array()
        .ok_or("the batch carries no requests array")?;

    requests
        .iter()
        .enumerate()
        .map(|(position, request)| answer_request(request, position))
        .collect()
}

/// One request row, read strictly, and the one observation it asks for.
fn answer_request(request: &Value, position: usize) -> Result<Value, Fault> {
    let where_ = format!("request {position}");
    let entry = closed_members(request, &["id", "op", "input"], &where_)?;
    let id = member_str(entry, "id", &where_)?;
    if id.is_empty() {
        return Err(format!("{where_} carries an empty id"));
    }
    let op = member_str(entry, "op", &format!("request {id}"))?;

    let observation = observe(op, &entry["input"], id)?;

    let mut result = Map::new();
    result.insert("id".into(), Value::from(id));
    result.insert("op".into(), Value::from(op));
    result.insert("observation".into(), observation);
    Ok(Value::Object(result))
}

/// One observation for one request, or a fault if the operation is not one
/// this bridge implements.
fn observe(op: &str, input: &Value, id: &str) -> Result<Value, Fault> {
    match op {
        "decode-base64url" => observe_decode_base64url(input, id),
        "hkdf-sha256" => observe_hkdf_sha256(input, id),
        "open-aes-gcm" => observe_open_aes_gcm(input, id),
        "seal-aes-gcm" => observe_seal_aes_gcm(input, id),
        "ecdh-p256" => observe_ecdh_p256(input, id),
        "p256-point" => observe_p256_point(input, id),
        "open-rsa-oaep" => observe_open_rsa_oaep(input, id),
        other => Err(format!("request {id} names operation {other:?}, which this bridge does not implement")),
    }
}

/// The strict field spelling: RFC 4648 section 5 alphabet, no padding, a
/// length that encodes a whole octet count, and zero unused trailing bits.
/// Which rule fired goes to stderr; the observation carries the one code.
fn observe_decode_base64url(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(input, &["value"], &where_)?;
    let value = member_str(members, "value", &where_)?;
    match decode_strict_base64url(value) {
        Ok(decoded) => Ok(observation("bytesHex", lower_hex(&decoded))),
        Err(why) => {
            eprintln!("bridge: {id} refused {value:?}: {why}.");
            Ok(refusal("invalid_base64url"))
        }
    }
}

/// One HKDF-SHA-256 invocation with an empty salt over the decoded `ikm` and
/// `info` octets, answering `length` octets. The operation defines no refusal.
fn observe_hkdf_sha256(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(input, &["ikmBase64url", "infoBase64url", "length"], &where_)?;
    let ikm = carrier_bytes(members, "ikmBase64url", id)?;
    let info = carrier_bytes(members, "infoBase64url", id)?;
    let length = member_length(members, "length", &where_)?;
    let okm = hkdf_sha256(&ikm, &info, length).map_err(|error| {
        format!("request {id} asks for {length} octets, and HKDF-SHA-256 would not answer: {error}")
    })?;
    Ok(observation("okmBase64url", encode_base64url(&okm)))
}

/// One output width, present and a JSON integer inside the bounds above.
///
/// `serde_json` reads `16.0` and `1.6e1` as floating-point numbers, and
/// `as_u64` answers nothing for them, so neither is rounded into a width
/// nobody asked for.
fn member_length(object: &Map<String, Value>, member: &str, what: &str) -> Result<usize, Fault> {
    let raw = &object[member];
    let value = raw
        .as_u64()
        .ok_or_else(|| format!("{what} carries {member} as {raw}, and it carries a non-negative whole number"))?;
    if !(HKDF_MIN_OCTETS..=HKDF_MAX_OCTETS).contains(&value) {
        return Err(format!(
            "{what} carries {member} as {value}, and one HKDF-SHA-256 expansion answers \
             {HKDF_MIN_OCTETS} through {HKDF_MAX_OCTETS} octets"
        ));
    }
    usize::try_from(value).map_err(|_| format!("{what} carries {member} as {value}"))
}

/// AES-GCM over one `ciphertext || tag` carrier. The key's width picks the
/// cipher. A key or nonce of another width is a request this bridge cannot
/// serve, named as such rather than cut to size. A tag that does not verify,
/// including a carrier shorter than the tag, is the refusal.
fn observe_open_aes_gcm(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(
        input,
        &["keyBase64url", "nonceBase64url", "ciphertextBase64url", "aadBase64url"],
        &where_,
    )?;
    let key = carrier_bytes(members, "keyBase64url", id)?;
    let nonce = carrier_bytes(members, "nonceBase64url", id)?;
    let carrier = carrier_bytes(members, "ciphertextBase64url", id)?;
    let aad = carrier_bytes(members, "aadBase64url", id)?;

    match gcm_open(&key, &nonce, &carrier, &aad).map_err(|error| format!("request {id} carries {error}"))? {
        Some(plaintext) => Ok(observation("plaintextBase64url", encode_base64url(&plaintext))),
        None => {
            eprintln!("bridge: {id} did not authenticate.");
            Ok(refusal("authentication_failed"))
        }
    }
}

/// The same carrier, sealed. The nonce arrives as an input, so a seal has one
/// determined answer, and the 16-octet tag goes on the end of the ciphertext.
/// The operation defines no refusal.
fn observe_seal_aes_gcm(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(
        input,
        &["keyBase64url", "nonceBase64url", "plaintextBase64url", "aadBase64url"],
        &where_,
    )?;
    let key = carrier_bytes(members, "keyBase64url", id)?;
    let nonce = carrier_bytes(members, "nonceBase64url", id)?;
    let plaintext = carrier_bytes(members, "plaintextBase64url", id)?;
    let aad = carrier_bytes(members, "aadBase64url", id)?;

    let sealed = gcm_seal(&key, &nonce, &plaintext, &aad).map_err(|error| format!("request {id} carries {error}"))?;
    Ok(observation("ciphertextBase64url", encode_base64url(&sealed)))
}

/// One ECDH agreement over P-256: the private JWK imported by its `d` scalar,
/// the peer's 65-octet uncompressed SEC 1 point imported by the crate's own
/// point decoder, and one agreement. The operation defines no refusal; a peer
/// value the crate cannot import is a request this bridge cannot serve.
fn observe_ecdh_p256(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(input, &["privateKeyJwk", "peerPointBase64url"], &where_)?;

    let jwk = ec_jwk(members, "privateKeyJwk", id)?;
    let d = jwk_octets(jwk, "d", "privateKeyJwk", id)?;
    let secret = p256_secret_key(&d)
        .map_err(|error| format!("request {id} carries a privateKeyJwk this bridge cannot import: {error}"))?;

    let peer_point = carrier_bytes(members, "peerPointBase64url", id)?;
    let peer = p256_public_key(&peer_point)
        .map_err(|error| format!("request {id} carries a peerPointBase64url the crate cannot import: {error}"))?;

    Ok(observation("sharedSecretBase64url", encode_base64url(&p256_ecdh(&secret, &peer))))
}

/// One public JWK written as the 65-octet uncompressed SEC 1 point. The bridge
/// lays `x` and `y` out as a point, the crate imports it, which refuses a point
/// off the curve, and the crate writes it back. The operation defines no
/// refusal.
fn observe_p256_point(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(input, &["publicKeyJwk"], &where_)?;

    let jwk = ec_jwk(members, "publicKeyJwk", id)?;
    let x = jwk_octets(jwk, "x", "publicKeyJwk", id)?;
    let y = jwk_octets(jwk, "y", "publicKeyJwk", id)?;
    let point = p256_point_from_coordinates(&x, &y).ok_or_else(|| {
        format!("request {id} carries a publicKeyJwk with a coordinate wider than the 32 octets P-256 carries")
    })?;
    let key = p256_public_key(&point)
        .map_err(|error| format!("request {id} carries a publicKeyJwk the crate cannot import: {error}"))?;

    Ok(observation("pointBase64url", encode_base64url(&p256_uncompressed_point(&key))))
}

/// One recorded RSA-OAEP ciphertext over SHA-256, MGF1 with the same hash and
/// no label, opened to the whole plaintext. A wrong private key, a ciphertext
/// that is not one modulus wide and a flipped octet all answer one
/// `unseal_failed`; `rsa` reports each as its one decryption error.
fn observe_open_rsa_oaep(input: &Value, id: &str) -> Result<Value, Fault> {
    let where_ = format!("the input of request {id}");
    let members = closed_members(input, &["ciphertextBase64url", "privateKeyJwk"], &where_)?;

    let jwk = jwk_object(members, "privateKeyJwk", id)?;
    let kty = jwk_str(jwk, "kty", "privateKeyJwk", id)?;
    if kty != "RSA" {
        return Err(format!("request {id} carries a privateKeyJwk with kty {kty:?}, not \"RSA\""));
    }
    let [n, e, d, p, q] = ["n", "e", "d", "p", "q"].map(|name| jwk_octets(jwk, name, "privateKeyJwk", id));
    let key = rsa_private_key(&n?, &e?, &d?, &p?, &q?)
        .map_err(|error| format!("request {id} carries a privateKeyJwk this bridge cannot import: {error}"))?;

    let carrier = carrier_bytes(members, "ciphertextBase64url", id)?;
    match rsa_oaep_sha256_open(&key, &carrier) {
        Ok(plaintext) => Ok(observation("plaintextBase64url", encode_base64url(&plaintext))),
        Err(error) => {
            eprintln!("bridge: {id} did not open: {error}.");
            Ok(refusal("unseal_failed"))
        }
    }
}

/// One input member as an EC JWK on P-256: an object with `kty` `EC` and
/// `crv` `P-256`. The caller reads the members its operation needs, and a
/// member the JWK carries beyond those is left alone, since RFC 7517 lets a
/// JWK carry more than one operation reads.
fn ec_jwk<'a>(members: &'a Map<String, Value>, member: &str, id: &str) -> Result<&'a Map<String, Value>, Fault> {
    let jwk = jwk_object(members, member, id)?;
    let kty = jwk_str(jwk, "kty", member, id)?;
    let crv = jwk_str(jwk, "crv", member, id)?;
    if kty != "EC" || crv != "P-256" {
        return Err(format!("request {id} carries a {member} with kty {kty:?} and crv {crv:?}, not EC P-256"));
    }
    Ok(jwk)
}

fn jwk_object<'a>(members: &'a Map<String, Value>, member: &str, id: &str) -> Result<&'a Map<String, Value>, Fault> {
    members[member]
        .as_object()
        .ok_or_else(|| format!("request {id} carries a {member} that is not a JSON object"))
}

fn jwk_str<'a>(jwk: &'a Map<String, Value>, name: &str, member: &str, id: &str) -> Result<&'a str, Fault> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("request {id} carries a {member} with no string {name}"))
}

/// One base64url JWK member decoded under the same strict rule as every other
/// field.
fn jwk_octets(jwk: &Map<String, Value>, name: &str, member: &str, id: &str) -> Result<Vec<u8>, Fault> {
    let spelled = jwk_str(jwk, name, member, id)?;
    decode_strict_base64url(spelled)
        .map_err(|why| format!("request {id} carries a {member}.{name} this bridge cannot decode: {why}"))
}

/// One JSON object holding exactly the named members, or a request this
/// bridge cannot serve. The contract calls the envelope, the request row and
/// every input closed, and a closed shape goes unenforced until something
/// checks it.
fn closed_members<'a>(raw: &'a Value, members: &[&str], what: &str) -> Result<&'a Map<String, Value>, Fault> {
    let object = raw.as_object().ok_or_else(|| format!("{what} is not a JSON object"))?;
    let unknown = object.keys().any(|name| !members.contains(&name.as_str()));
    let absent = members.iter().any(|name| !object.contains_key(*name));
    if unknown || absent {
        // serde_json's map keeps its keys sorted, so two runs report the same
        // shape the same way.
        let carried: Vec<&str> = object.keys().map(String::as_str).collect();
        return Err(format!(
            "{what} carries {{{}}}, and it carries {{{}}} exactly",
            carried.join(", "),
            members.join(", ")
        ));
    }
    Ok(object)
}

/// One member that must be present and a string.
fn member_str<'a>(object: &'a Map<String, Value>, member: &str, what: &str) -> Result<&'a str, Fault> {
    object
        .get(member)
        .ok_or_else(|| format!("{what} carries no {member}"))?
        .as_str()
        .ok_or_else(|| format!("{what} carries a non-string {member}"))
}

/// One base64url input member decoded to raw octets. Every carrier literal the
/// harness sends is canonical, so a spelling that fails the strict rule here
/// makes a batch this bridge cannot serve rather than a request it answers.
fn carrier_bytes(object: &Map<String, Value>, member: &str, id: &str) -> Result<Vec<u8>, Fault> {
    let value = member_str(object, member, &format!("the input of request {id}"))?;
    decode_strict_base64url(value)
        .map_err(|why| format!("request {id} carries a {member} this bridge cannot decode: {why}"))
}

fn lower_hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

fn observation(member: &str, value: String) -> Value {
    let mut object = Map::new();
    object.insert(member.into(), Value::from(value));
    Value::Object(object)
}

fn refusal(code: &str) -> Value {
    observation("refused", code.to_string())
}
