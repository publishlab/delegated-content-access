#!/usr/bin/env python3
# Re-derives the recorded chain-key bytes from the specification and fails
# on any disagreement.
#
#     python3 verification/vectors/check-chain-key-primitives.py
#     python3 verification/vectors/check-chain-key-primitives.py --neutral copy.json
#
# The neutral rows and the conformance hkdf/01-hkdf/11 expectations are literal
# recorded observations with no generator. This script is their independent
# check: it builds the Root, Step and Leaf contexts of
# docs/spec-profile--chain-keys.md section 6.4 itself, runs HKDF-SHA-256 per
# RFC 5869 with an empty salt (section 6.3) over hmac and hashlib, and compares
# every recorded neutral info, ikm and okm. The conformance rows are checked as
# plain HKDF-SHA-256: each recorded okm must follow from its own recorded ikm,
# info and length. Their contexts are not compared with the neutral rows,
# because that corpus is held and may record contexts of an earlier
# construction identifier. It also re-derives every value of the JavaScript
# canonical fixture that section 6 and the label mapping of section 7.3 fix.
# It imports no repository code and writes nothing.
#
# Exit 0: every value agrees. Exit 1: a recorded value disagrees; each one is
# printed with both values. Exit 2: an input could not be read, so nothing was
# verified.

import argparse, base64, calendar, hashlib, hmac, json, os, struct, sys

CONSTRUCTION_ID = "dca-construction-chain-keys"
HERE = os.path.dirname(os.path.abspath(__file__))
NEUTRAL = os.path.join(HERE, "v1", "profiles", "dca-profile-chain-keys", "chain-key-primitives.json")
CASES = os.path.join(HERE, "..", "conformance-primitives", "_shared", "cases", "v1", "cases.json")
FIXTURE = os.path.join(HERE, "..", "..", "js", "extensions", "chain-keys", "test", "fixtures",
                       "dca-profile-chain-keys.vectors.json")


def b64u(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(ikm, info, width=16):
    prk = hmac.new(b"", ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < width:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm, counter = okm + block, counter + 1
    return okm[:width]


def string(value):
    raw = value.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def context(domain, group, cpd, pm, w, position):
    return bytes([domain]) + string(CONSTRUCTION_ID) + string(group) + struct.pack(">HHIH", cpd, pm, w, position)


class Window:
    """Every chain key C[i] of one window, walked back from the Root."""

    def __init__(self, secret, group, cpd, pm, w):
        self.secret, self.group, self.cpd, self.pm, self.w = secret, group, cpd, pm, w
        self.n = 1440 // cpd // pm
        self.chain_key = {self.n - 1: hkdf(secret, self.info(1, self.n - 1))}
        for i in range(self.n - 2, -1, -1):
            self.chain_key[i] = hkdf(self.chain_key[i + 1], self.info(2, i))

    def info(self, domain, i):
        return context(domain, self.group, self.cpd, self.pm, self.w, i)

    def root(self):
        return self.secret, self.info(1, self.n - 1), self.chain_key[self.n - 1]

    def step(self, i):
        return self.chain_key[i + 1], self.info(2, i), self.chain_key[i]

    def leaf(self, i):
        return self.chain_key[i], self.info(3, i), hkdf(self.chain_key[i], self.info(3, i))


def coordinate(label, cpd, pm):
    """Section 7.3: YYMMDDTHHMM to (windowStart, position)."""
    m = calendar.timegm((2000 + int(label[0:2]), int(label[2:4]), int(label[4:6]),
                         int(label[7:9]), int(label[9:11]), 0)) // 60
    w = m - m % (1440 // cpd)
    return w, (m - w) // pm


class Checker:
    def __init__(self):
        self.checked, self.failed = 0, 0

    def same(self, where, recorded, derived):
        self.checked += 1
        if recorded != derived:
            self.failed += 1
            print(f"MISMATCH {where}\n  recorded {recorded}\n  derived  {derived}", file=sys.stderr)


def neutral_rows():
    """The eleven rows, in recorded order, as (ikm, info, okm) octets."""
    s7, s8 = bytes([7]) * 32, bytes([8]) * 32
    a = Window(s7, "premium", 2, 15, 29353680)
    b = Window(s7, "locked-data", 4, 5, 29353680)
    c = Window(s7, "premium", 1, 5, 29352960)
    d = Window(s8, "premium", 2, 15, 29353680)
    return [a.root(), b.root(), c.root(), d.root(), a.step(0), a.step(9), a.step(a.n - 2),
            a.leaf(0), a.leaf(9), b.leaf(b.n - 1), c.leaf(c.n - 1)]


def check_rows(check, source, recorded):
    derived = neutral_rows()
    check.same(f"{source} row count", len(recorded), len(derived))
    for (name, inp, out), (ikm, info, okm) in zip(recorded, derived):
        check.same(f"{source} {name}: length", inp.get("length"), 16)
        check.same(f"{source} {name}: ikm", inp.get("ikmBase64url"), b64u(ikm))
        check.same(f"{source} {name}: info", inp.get("infoBase64url"), b64u(info))
        check.same(f"{source} {name}: okm", out.get("okmBase64url"), b64u(okm))


def check_hkdf_rows(check, source, recorded):
    """Each row's okm is HKDF-SHA-256 of its own ikm and info, with an empty salt."""
    for name, inp, out in recorded:
        check.same(f"{source} {name}: length", inp.get("length"), 16)
        okm = hkdf(unb64u(inp["ikmBase64url"]), unb64u(inp["infoBase64url"]), inp["length"])
        check.same(f"{source} {name}: okm", out.get("okmBase64url"), b64u(okm))


def check_fixture(check, doc):
    check.same("fixture constructionIdentity", doc.get("constructionIdentity"), CONSTRUCTION_ID)
    # Each collection carries a distinct part of the fixture's claims. Empty
    # collections must not make their corresponding checks pass vacuously.
    for name in ("cases", "separation", "edges"):
        check.same(f"fixture {name} present", isinstance(doc.get(name), list) and len(doc[name]) > 0, True)
    for case in doc["cases"]:
        cpd, pm = case["chainsPerDay"], case["periodMinutes"]
        win = Window(bytes.fromhex(case["secretHex"]), case["accessGroup"], cpd, pm, case["windowStart"])
        at = f"fixture {case['id']}"
        check.same(f"{at}.N", case["N"], win.n)
        check.same(f"{at}.label", [case["windowStart"], case["position"]], list(coordinate(case["label"], cpd, pm)))
        check.same(f"{at}.rootChainKey", case["rootChainKey"], b64u(win.chain_key[win.n - 1]))
        check.same(f"{at}.chainKeyAfterOneStep", case["chainKeyAfterOneStep"], b64u(win.chain_key[win.n - 2]))
        check.same(f"{at}.periodKey", case["periodKey"], b64u(win.leaf(case["position"])[2]))
        check.same(f"{at}.rootInfoHex", case["rootInfoHex"], win.info(1, win.n - 1).hex())
        check.same(f"{at}.stepInfoHex", case["stepInfoHex"], win.info(2, win.n - 2).hex())
        check.same(f"{at}.leafInfoHex", case["leafInfoHex"], win.info(3, case["position"]).hex())
        check.same(f"{at}.expansion length", len(case["expansion"]), win.n)
        for i, period_key in enumerate(case["expansion"]):
            check.same(f"{at}.expansion[{i}]", period_key, b64u(win.leaf(i)[2]))
        for label, chain_key in case["cutoffChainKeys"].items():
            w, i = coordinate(label, cpd, pm)
            other = win if w == win.w else Window(win.secret, win.group, cpd, pm, w)
            check.same(f"{at}.cutoffChainKeys[{label}]", chain_key, b64u(other.chain_key[i]))
    # An empty or skipped separation list would otherwise pass with nothing derived.
    check.same("fixture separation rows present", len(doc["separation"]) >= 1, True)
    separated = 0
    for row in doc["separation"]:
        for side, key in (("a", "periodKeyA"), ("b", "periodKeyB")):
            x, at = row[side], f"fixture {row['id']}.{side}"
            check.same(f"{at}.construction", x.get("construction"), CONSTRUCTION_ID)
            cpd, pm = x["chainsPerDay"], x["periodMinutes"]
            win = Window(bytes.fromhex(x["secretHex"]), x["accessGroup"], cpd, pm, x["windowStart"])
            check.same(f"{at}.N", x["N"], win.n)
            check.same(f"{at}.label", [x["windowStart"], x["position"]], list(coordinate(x["label"], cpd, pm)))
            check.same(f"fixture {row['id']}.{key}", row[key], b64u(win.leaf(x["position"])[2]))
        separated += 1
    check.same("fixture separation rows checked", separated, len(doc["separation"]))
    for edge in doc["edges"]:
        derived = coordinate(edge["label"], edge["chainsPerDay"], edge["periodMinutes"])
        check.same(f"fixture {edge['id']}.label", [edge["windowStart"], edge["position"]], list(derived))


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)


def check_set_members(check, vector_path):
    directory = os.path.dirname(os.path.abspath(vector_path))
    try:
        members = sorted(name for name in os.listdir(directory)
                         if name.endswith(".json") and name != "set.json")
    except OSError as e:
        print(f"cannot list {directory}: {e}", file=sys.stderr)
        sys.exit(2)
    check.same("chain-key set members", members, [os.path.basename(vector_path)])


def main():
    p = argparse.ArgumentParser(description="Independent check of the recorded chain-key bytes.")
    p.add_argument("--neutral", default=NEUTRAL)
    p.add_argument("--cases", default=CASES)
    p.add_argument("--fixture", default=FIXTURE)
    args = p.parse_args()

    check = Checker()
    check_set_members(check, args.neutral)
    doc = load(args.neutral)
    labels = doc["driver"]["labels"]
    operations = doc["input"]["operations"]
    observations = doc["expected"]["observations"]
    check.same("neutral label count", len(labels), 11)
    check.same("neutral input count", len(operations), 11)
    check.same("neutral expected count", len(observations), 11)
    check_rows(check, "neutral", [(label, op["input"], obs) for label, op, obs in
                                  zip(labels[:11], operations[:11], observations[:11])])
    print(f"neutral: {check.checked} values", file=sys.stderr)

    before = check.checked
    wanted = [f"hkdf/{k:02d}" for k in range(1, 12)]
    cases = {c["id"]: c for c in load(args.cases)["cases"]}
    check.same("conformance row count", sum(i in cases for i in wanted), 11)
    check_hkdf_rows(check, "conformance", [(i, cases[i]["input"], cases[i]["expected"]) for i in wanted if i in cases])
    print(f"conformance: {check.checked - before} values", file=sys.stderr)

    before = check.checked
    check_fixture(check, load(args.fixture))
    print(f"fixture: {check.checked - before} values", file=sys.stderr)

    print(f"{'FAIL' if check.failed else 'PASS'}: {check.checked} values checked, {check.failed} disagree")
    sys.exit(1 if check.failed else 0)


main()
