# Proposal: content transforms

Status: Proposal
Target: [spec--content-protection.md Section 8](spec--content-protection.md#8-content-representations-and-extension-profiles); [spec--data-format.md](spec--data-format.md)

This document has no protocol authority. If the editors accept it, they move
its text into the targets; if they decline it, they remove this file.

## Introduction

DCA v1 already lets the publisher list transforms in `contentEncodings`. It
says when the publisher applies them, when the client reverses them, how a
failure affects one item, and where implementations enforce limits. It does
not name a transform. This proposal adds the first named transform profile,
starting with gzip.

## Motivation

Wire: ciphertext does not compress, so page-level HTTP compression gains
nothing on a sealed item, while unpadded base64url makes it larger. The
publisher must compress the content before encryption. The size gain from
gzip is unmeasured here, so this proposal makes no claim about it.

Client: after authenticated decryption, the client reverses the listed
transforms. Implementations therefore need the same transform names, order,
limits and unsupported-transform behavior even if the reference code remains
an extension.

## Specification

## 1. Change

Lands in: [spec--content-protection.md Section 8](spec--content-protection.md#8-content-representations-and-extension-profiles)

Section 8 and the data format already define the ordered list and its processing
order. This proposal adds what they leave open: the transform name a publisher
may list, its forward and inverse operations, and any shared client limits.

Decision needed: whether DCA v1 selects gzip as its first named transform, or
publishes the generic list with no named transform. The merits of gzip itself
remain a separate decision.

Sections 2 through 4 restate the existing behavior that a named transform must
follow.

## 2. Transform descriptor

Lands in: [spec--data-format.md Section 4.1](spec--data-format.md#41-contentdata)

The item record carries the optional `contentEncodings` member: a non-empty
dense array of non-empty strings in application order, repetitions significant,
names opaque, case-sensitive and not normalized. An absent member means the base
representation; an empty or malformed array is an item record failure. A
publisher MUST list every forward transform it applied, in application order,
and MUST omit the member when it applied none.

## 3. Sealing

Lands in: [spec--content-protection.md Section 8](spec--content-protection.md#8-content-representations-and-extension-profiles)

The publisher applies the named transforms in listed order to the base
representation, then encrypts the resulting octets under Section 3.3. A
publisher component MAY receive octets that have already been transformed,
with a matching list. The producer remains responsible for declaring the right
sequence. The publisher encrypts the transformed octets as plaintext; those
octets are not content AAD. DCA v1 also leaves `contentEncodings` out of content
AAD. BIND protects a key sealed for an issuer and coordinate, while base
exact-period wrapping uses empty AES-GCM additional data. Neither authenticates
the representation metadata. Deleting or changing `contentEncodings` may
therefore produce undecoded output or fail that item, but it does not change
either base transcript.

Decision needed: whether the transform profile authenticates the list, or v1
keeps it outside content AAD.

## 4. Opening

Lands in: [spec--content-protection.md Section 8](spec--content-protection.md#8-content-representations-and-extension-profiles)

Before opening that item's content key, the client MUST validate the complete
list and confirm that it supports every named inverse transform.
It MUST authenticate and decrypt under Section 5.4 first, then apply the inverse
transforms in reverse list order. It MUST NOT pass unauthenticated bytes to a
decoder and MUST NOT release intermediate or partially decoded bytes.

A malformed list, an unsupported name, a transform failure, a non-octet
transform result or a limit breach is an item failure. The client MUST NOT retry
that item as the base representation and MUST NOT suppress a valid sibling.
Every implementation MUST enforce finite limits on layer count, name bytes, the
bytes into and out of each transform, total output and decoding work or time.

Decision needed: whether the named-transform profile fixes interoperable bounds,
or the limits stay implementation and deployment choices.

## 5. Evidence

Lands in: undecided

Each supported runtime must seal a fixture with the transform listed, open it
back to the original octets, and refuse an unsupported name, a malformed list
and bytes that contradict their declaration. The experimental extension at
`js/v1/extensions/content-compression/` contributes gzip to the layered-content
seam. The editors have not folded the experiment results into this proposal, so
they attach no executable proof.

## 6. Results

Pending.
