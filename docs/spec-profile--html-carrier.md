# DCA HTML carrier profile

Status: Public Working Draft

## Abstract

This optional profile selects markup delivery and extraction for a protected
DCA document. It assigns publisher and client duties and states when a JSON
publication remains necessary for baseline-only clients.

## 1. Introduction

`dca-profile-html-carrier` depends on `dca-profile-baseline`. The shared
[data format](spec--data-format.md#3-markup-delivery) defines markup syntax
and extraction; this document defines the profile's role and selection duties.
The [profile catalogue](spec--profiles.md) records its dependency.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Profile selection and role duties

This optional profile composes the baseline with the markup delivery in
[data format Section 3](spec--data-format.md#3-markup-delivery). A publisher
embeds one protected delivery in an HTML document, and a client extracts it.
The profile changes only the publisher and client roles. Issuers acquire no
duty: the unlock request, the issuer's decision and the response are the
same for either carrier.

A publisher and a client that claim the profile implement the producer and
consumer rules of
[data format Section 3](spec--data-format.md#3-markup-delivery). Every later
step, from structural admission to item opening, is the baseline's.

The publisher's publication arrangement selects the carrier for each
delivery. A publisher MAY publish a delivery as HTML only, as the JSON
document only, or as both. An HTML-only publication requires a client that
implements this profile. A deployment that promises service to baseline-only
clients MUST offer the JSON document for that publication
([catalogue Section 3.6](spec--profiles.md#36-compatibility-with-a-baseline-only-client));
a conversion that those clients cannot use does not meet the promise.

Selecting `dca-profile-browser-origin` does not select this profile, and this
profile does not select browser-origin admission. A browser page can consume
the JSON document, and a non-browser client can extract a delivery from
HTML. The profile covers extraction only. Placing opened content in a page is
outside it.

The profile defines no carrier discovery, retrieval endpoint, negotiation or
fallback between carriers. How a client obtains a document stays with the
host, and extraction establishes no provenance for the document it reads
([security model Section 8.5](spec--security-model.md#what-opening-proves)).

## 3. Security considerations

HTML extraction establishes no provenance for the document. The selected
[security model](spec--security-model.md#what-opening-proves) governs opening.

## 4. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [DCA data format](spec--data-format.md)
- [DCA profile catalogue](spec--profiles.md)
- [DCA security model](spec--security-model.md)
