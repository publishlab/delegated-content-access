# Proposal: detached content

Status: Proposal
Target: [spec--content-protection.md Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling); [spec--data-format.md](spec--data-format.md)

This document has no protocol authority. If the editors accept it, they move
its text into the targets; if they decline it, they remove this file.

## Introduction

This proposal gives each detached item one locator. The publisher leaves that
item's ciphertext out of the page, and the client fetches it later. The proposal
does not yet choose an API, CDN, locator grammar, fetch protocol or cache
behavior. The client opens the fetched bytes by the same rules as inline
ciphertext.

## Motivation

Page budget: content usually contributes most of the DCA bytes in a page. With
detached content, the publisher puts only the item record in the page.

Interop: detached content and detached key supply could share one locator and
fetch layer. DCA defines neither today. The two proposals should share it only
if both extensions are adopted.

## Specification

## 1. Change

Lands in: [spec--content-protection.md Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling)

The current spec already says in
[Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling):
when inline ciphertext is absent, the client obtains it later without changing
how it resolves the key. The publisher must supply the exact ciphertext made
for that item's key, nonce and AAD. The spec deliberately leaves location,
authorization, fetching and freshness undefined.

This proposal adds a way for the client to associate fetched ciphertext with an
item record it already admitted. The publisher must not silently encrypt new
bytes under a different key, nonce or AAD while reusing the old record.

Decision needed: should DCA standardize deferred ciphertext delivery, or keep
the current deployment-defined model?

## 2. Pointer

Lands in: [spec--data-format.md Section 4.1](spec--data-format.md#41-contentdata)

The current item record has no locator member. This proposal adds one to a
detached item and omits that item's inline ciphertext. It still needs a member
name, a value grammar, and rules for an unavailable or invalid fetch. The
locator only tells the client where to fetch; possessing it must not grant a
key or plaintext.

Detached key supply could use the same locator and fetch layer, but the two
proposals have not defined it. They still need to choose its grammar, transport,
media type, authorization, size and freshness limits, cache rules and response
shape.

Decision needed: should the one-locator/no-inline construction remain the only
form, or may an item name more than one locator, including one per
representation?

## 3. Fetching and matching

Lands in: [spec--content-protection.md Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling)

The client treats bytes fetched through an item's locator as ciphertext for that
item alone. It must receive the exact ciphertext the publisher produced for the
item's existing `contentKey`, nonce and AAD. Before the client can validate the
response itself, the profile must define how that response is framed.

Decision needed: what, if anything beyond the existing AEAD tuple, correlates a
retrieval result to an item record?

## 4. Opening

Lands in: [spec--content-protection.md Section 5.4](spec--content-protection.md#54-content-opening-and-containment)

The current spec requires the client to apply the validation and AEAD opening
rules in
[Section 5.4](spec--content-protection.md#54-content-opening-and-containment)
regardless of how the ciphertext arrived. If authentication fails, the client
releases no plaintext and fails only that item. This proposal handles an
unavailable locator or invalid fetched response the same way. It does not yet
define HTTP status handling, a response grammar or retries.

## 5. Evidence

Lands in: undecided

`js/v1/experiments/` holds no detached-content experiment, so no executable
evidence is attached. Once the fetch contract is defined, tests must show that
the client opens ciphertext made for the record's existing key,
nonce and AAD. Substituted or newly encrypted bytes must release no plaintext
and must not suppress a valid sibling item.

## 6. Results

Pending.
