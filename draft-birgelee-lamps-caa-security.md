---
title: "CAA Security Tag for Cryptographic Domain Validation"
abbrev: "CAA Security Tag"
category: exp

docname: draft-birgelee-lamps-caa-security-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
 - PKI
 - CAA
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "birgelee/draft-caa-security-tag"
  latest: "https://birgelee.github.io/draft-caa-security-tag/draft-birgelee-lamps-caa-security.html"

author:
 -
    fullname: Henry Birge-Lee
    organization: Princeton University
    email: birgelee@princeton.edu

normative:

informative:


--- abstract

CAA "security" tags are a type of CAA record (defined in RFC 6844) with the critical flag set that specify that for a certificate to be issued, the issuance process must be conducted in a manner that has cryptographic guarantees and does not rely on plain-text network connections. Cryptographic issuance procedures are authenticated and resilient against attacks by both on and off path network attackers which may be between the CA and the domain contained in the certificate. This document defines the syntax of “security” CAA records as well as acceptable means for validating domains in a cryptographic manner.


--- middle

# Introduction

A "security" CAA record is compliant with RFC 6844 and puts restrictions on the circumstances under which a CA can sign a certificate for a given domain. A “security” CAA record on a domain implies that validation for this domain must be done in a manner that offers security against network adversaries even if an adversary is capable of intercepting and/or modifying domain-control-validation-related communication between the CA and the domain being validated. Issuance of a certificate to a domain with a "security" CAA tag MUST follow one of the specified Cryptographic Domain Validation (CDV) methods outlined in this document or future extensions. CDV methods MUST rely on cryptographic protocols (like DNSSEC or DoH/DoT) that offer security properties even in the presence of man-in-the-middle adversaries that can intercept any communication which occurs over the public Internet.

Not all CDV methods are in themselves compliant with the CA/Browser Forum Baseline Requirements for TLS server certificate issuance. Any CDV method that does not additionally meet the CA/Browser Forum's Baseline Requirements for TLS server certificate issuance must be used in conjunction with a method that satisfies the CA/Browser Forums Baseline Requirements for TLS server certificate issuance. Such methods are indicated in their descriptions. 




# Conventions and Definitions

{::boilerplate bcp14-tagged}




# CAA "security" Tag Protection


A "security" CAA tag SHOULD be protected with a valid DNSSEC signature chain going back to the ICANN DNSSEC root or hosted on authoritative DNS servers that CAs have authenticated communication channels with. Any High-security-validation CAA record not protected by such a signature MAY not benefit from the security properties outlined in this document. If it is not possible to have a DNSSEC signature chain back to the ICANN root, High-Security-Validation CAA records SHOULD alternately be hosted in an authoritative DNS resolver that supports recursive-to-authoritative DNS over TLS or DNS over HTTPS per RFC 9539. CAs SHOULD also require recursive-to-authoritative DNS over TLS or DNS over HTTPS communication (and not permit standard unencrypted DNS connections) for DNS providers that host High-Security-Validation CAA records. This prevents downgrade attacks where an adversary attempts to interfere with the establishment of a DNS over TLS or DNS over HTTPS encrypted channel and cause a fallback to unencrypted DNS over UDP/TCP.

Serving "security" CAA records over authenticated DNS channels is critical to the security of the records because a "security" CAA record not protected by authenticated DNS may be suppressed by an adversary that can manipulate DNS responses. This could potentially allow the adversary to downgrade validation to use a non-high-security method and undermine the security properties of the "security" tag. 


# Security Considerations

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
