# Proposal: derived content AAD

Status: Proposal
Target: [spec--content-protection.md Section 3.2](spec--content-protection.md#32-content-aad); [spec--data-format.md](spec--data-format.md)

This document has no protocol authority. If the editors accept it, they move
its text into the targets; if they decline it, they remove this file.

## Introduction

This proposal has the client rebuild the content AAD from a defined
`resourceId|version|contentName` transcript instead of reading the shipped item
`aad` string. Current v1 still requires the carried string; this proposal does
not make rebuilding current behavior.

## Motivation

Wire: the publisher currently builds
`resourceId "|" "1" "|" contentName` and ships that string in every
`contentData[contentName].aad`. This proposal can remove those repeated bytes
only after it names one unambiguous source for every field.

Simpler wire: the publisher sends one fewer member, and the client has one fewer
value to validate and keep consistent. If someone moves a record to another
slot, the client rebuilds different AAD and the record can fail to open. That
does not repair authorization or replace BIND. It only stops the publisher from
carrying its chosen AAD spelling beside every item.

## Specification

## 1. Change

Lands in: [spec--content-protection.md Section 3.2](spec--content-protection.md#32-content-aad)

This proposal has the client rebuild content AAD from page values instead of
reading the item's `aad` member. Carried versus rebuilt AAD is still open.
Rebuilding it does not repair authorization under the current attacker model.

Decision needed: whether the `aad` member leaves the format or stays required
and ignored.

## 2. AAD transcript

Lands in: [spec--content-protection.md Section 3.2](spec--content-protection.md#32-content-aad),
[spec--data-format.md Section 4.1](spec--data-format.md#41-contentdata)

The client rebuilds the `resourceId "|" "1" "|" contentName` join from
[Section 3.2](spec--content-protection.md#32-content-aad): that field order,
one `|` octet between each pair, and no leading or trailing delimiter. It uses
the exact UTF-8 bytes of that string as associated data. Both variable fields
exclude `|`. The proposal must still say where the client gets `resourceId`.
It cannot use the optional readable `resource` object, which is diagnostic and
not an authenticated source for AAD.

Related: [spec--sealed-key-envelopes.md Section 3](spec--sealed-key-envelopes.md#3-bind).
BIND is a separate canonical `|` join that the issuer rebuilds to bind its
sealed-key payload to a coordinate; it does not authenticate content ciphertext
or content AAD. Base exact-period wrapping also uses no AES-GCM additional data.
The content AAD carries no `dca-bind-v1` prefix, kind field or `renderId`.

Decision needed: keep the literal `1`, or define a separately versioned
transcript. The client may use the unsigned page `version` to choose a grammar,
but MUST NOT put that value into the rebuilt authenticated bytes.

## 3. Sealing

Lands in: [spec--content-protection.md Section 3.3](spec--content-protection.md#33-content-encryption)

If adopted, the publisher builds the transcript and supplies its UTF-8 bytes as
AES-GCM associated data. Before implementations can do that consistently, the
spec must name the `resourceId` source and version discriminator.

## 4. Opening

Lands in: [spec--content-protection.md Section 5.4](spec--content-protection.md#54-content-opening-and-containment)

If adopted, the client derives AAD from the named source and the slot it fills,
then supplies those bytes to AEAD opening. The spec must say how the client
fails one item when an input is missing or malformed or the tag fails. It must
also say whether the publisher removes `aad`, or whether the client rejects or
ignores a carried value.

## 5. Evidence

Lands in: undecided

The experiment at `js/v1/experiments/derived-content-aad/` compares the
derivation against the carried `aad` member on the checked-in fixtures. The
editors have not folded the experiment results into this proposal.

## 6. Results

Pending.
