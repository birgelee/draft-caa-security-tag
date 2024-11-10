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

CAA "security" tags are a type of CAA record (defined in RFC 6844) with the critical flag set that specify that for a certificate to be issued, the issuance process must be conducted in a manner that has cryptographic guarantees and does not rely on plain-text network connections. Cryptographic domain validation proceedjures are authenticated and resilient against attacks by both on and off path network attackers which may be between the CA and the domain contained in the certificate. This document defines the syntax of "security" CAA records as well as acceptable means for validating domains in a cryptographic manner.


--- middle

# Introduction

A "security" CAA record is compliant with RFC 6844 and puts restrictions on the circumstances under which a CA can sign a certificate for a given domain. A “security” CAA record on a domain implies that validation for this domain must be done in a manner that offers security against network adversaries even if an adversary is capable of intercepting and/or modifying domain-control-validation-related communication between the CA and the domain being validated. Issuance of a certificate to a domain with a "security" CAA tag MUST follow one of the specified Cryptographic Domain Validation (CDV) methods outlined in this document or future extensions. CDV methods MUST rely on cryptographic protocols (like DNSSEC or DoH/DoT) that offer security properties even in the presence of man-in-the-middle adversaries that can intercept any communication which occurs over the public Internet.

Not all CDV methods are in themselves compliant with the CA/Browser Forum Baseline Requirements for TLS server certificate issuance. Any CDV method that does not additionally meet the CA/Browser Forums Baseline Requirements for TLS server certificate issuance must be used in conjunction with a method that satisfies the CA/Browser Forums Baseline Requirements for TLS server certificate issuance. Such methods are indicated in their descriptions.



# Conventions and Definitions

{::boilerplate bcp14-tagged}


# CAA "security" Tag Protection


A "security" CAA tag SHOULD be protected with a valid DNSSEC signature chain going back to the ICANN DNSSEC root or hosted on authoritative DNS servers that CAs have authenticated communication channels with. Any High-security-validation CAA record not protected by such a signature MAY not benefit from the security properties outlined in this document. If it is not possible to have a DNSSEC signature chain back to the ICANN root, High-Security-Validation CAA records SHOULD alternately be hosted in an authoritative DNS resolver that supports recursive-to-authoritative DNS over TLS or DNS over HTTPS per RFC 9539. CAs SHOULD also require recursive-to-authoritative DNS over TLS or DNS over HTTPS communication (and not permit standard unencrypted DNS connections) for DNS providers that host High-Security-Validation CAA records. This prevents downgrade attacks where an adversary attempts to interfere with the establishment of a DNS over TLS or DNS over HTTPS encrypted channel and cause a fallback to unencrypted DNS over UDP/TCP.

Serving "security" CAA records over authenticated DNS channels or using authenticated DNS records (i.e., DNSSEC) is critical to the effectiveness of the records because a "security" CAA record not protected by authenticated DNS may be suppressed by an adversary that can manipulate DNS responses. This could potentially allow the adversary to downgrade validation to use a non-high-security method and undermine the security properties of the "security" tag.


# Security CAA Record Syntax

The flags field of the security tag MUST have the critical bit set in the flags byte of the CAA record.

The \"security\" tag MUST have the tag field of the CAA record be the word \"security\".

A single domain CANNOT have multiple "security" tags specified. A domain's entire cryptographic domain validation policy MUST be encoded into a single "security" tag. If a CA finds a domain that has multiple "security" CAA tags at the same FQDN, the CA MUST block issuance.

The value field of the "security" tag MUST be one of three values

1. an empty string.
2. entirely whitespace.
3. a property\_list as defined in this document.

Values 1. and 2. MUST be treated identically as an empty value field.

A property\_list is defined by the following syntax

``[whitespace]<property>[whitespace][,[whitespace]<property>[whitespace] ...]``

A property is defined as

  ``<property_name>[whitespace][(property_list)]``

The optional property\_list specified in parenthesis after each property contains parameters associated with that property.

A property\_list can be arbitrarily long. Whitespace between properties is ignored. properties are comma-separated. property\_lists MUST NOT be empty \(i.e., property\_lists must have at least one property\). All properties specified in a property\_list MUST be unique. A property\_list MUST NOT have two of the same properties specified even if they contain different parameters.





# Well-known Properties

The top-level property\_list MAY contain the following properties.

1. **methods** If specified, this property MUST have parameters listing various cryptographic domain validation methods that can be used to validate that particular domain. A CA MUST only use one of the methods specified in the parameters value_list to perform cryptographic domain validation. If there is no method specified that the CA is capable of complying with, the CA MUST deny issuance.

2. **options** If specified, this property MUST have parameters listing various options. A CA SHOULD try to honor any option specified in this list. If a CA does not understand an option or does not have that option implemented the, CA MAY proceed with issuance.

3. **options-critical** If specified, this property MUST have parameters listing various options. To proceed with issuance, a CA MUST understand and implement all options specified in the options-critical parameter's property-list

The top-level property\_list MAY contain additional properties and a CA MAY proceed with issuance even if it does not understand these additional properties. Subsequent RFCs MAY standardize properties

# Permissible Methods

The following properties MAY be specified as parameters of the "methods" property. Each method specifies particular aspects of certificate issuance that MUST be satisfied for a certificate to be issued using that method. While some methods entail the use of CA/Browser Forum-compliant domain control validation methods, others do not entail CA/Browser Forum-compliant domain control validation and must be used in conjunction with a CA/Browser Forum-compliant domain control validation method to permit certificate issuance.



1. **secure-dns-record-change:** This method involves an applicant showing control of a DNSSEC-protected DNS record or a record that was retrieved via a DoH or DoT tunnel to the relevant authoritative nameservers used in the DNS resolution. This can be done via 1\) the validation method "DNS Change" specified in the CA/Browser Forum's Baseline Requirements for the Issuance and Management of Publicly‐Trusted TLS Server Certificates \(Section 3.2.2.4.7\) or 2\) the "dns-01" method of the ACME RFC 8555. For this method to be satisfied, the FQDN where the DNS change is demonstrated MUST be protected by DNSSEC or lookups to the relevant authoritative nameservers MUST be conducted over authenticated channels \(e.g., DoH/DoT\).

2. **http-validation-over-tls:** This method involves the completion of an HTTP domain validation challenge over an HTTPS session using TCP port 443 where the server authenticates with an existing publicly-trusted valid certificate covering the domain in question. The certificate cannot be self-signed or expired. This method MAY be directly satisfied while a CA is performing the "Agreed‑Upon Change to Website v2" domain control validation method specified in the the CA/Browser Forum's Baseline Requirements for the Issuance and Management of Publicly‐Trusted TLS Server Certificates \(Section 3.2.2.4.18\). The ACME "http-01" challenge specified in RFC 8555 does not permit the use of HTTPS or port 443 when a CA is contacting the domain in question. A CA MAY still satisfy the **http-validation-over-tls** method even if it does not initiate connections to port 443 for HTTP challenges so long as either 1\) the connection initiated to port 80 serves a redirect to the same domain name over HTTPS at port 443 and the connection to the domain at port 443 servers a valid, trusted certificate or 2\) in addition to contacting the domain over port 80 the CA also contacts the domain over port 443 using HTTPS and the connection is established with a valid, trusted certificate and the same challenge value is observed. Operators of security-critical domains MAY choose not to permit this method since, unlike other cryptographic domain validation methods specified in this document, its security relies on no malicious certificates existing for a domain at time of the creation of the "security" tag in the domain's policy.

3. **known-account-specifier:** For a CA to issue a certificate using this method 1) there must exist a unique identifier for a CA subscriber account that is communicated with the CA out-of-band, over authenticated DNS lookups, or in another manner that is immune to man-in-the-middle adversaries 2) the CA may only issue a certificate to an applicant that has authenticated itself to the CA as having access to that specified subscriber account. A CA does not have permission to issue under this method unless both of these criteria are met. Once these criteria have been met, the CA MUST additionally perform a validation method that is compliant with the Baseline Requirements for the Issuance and Management of Publicly‐Trusted TLS Server Certificates. One acceptable way of including this account identifier is with the CAA ACME account URI extension in an authenticated DNS record record.



4. **private-key-control:** This method involves an applicant showing control of a private key that corresponds to a public key placed in a DNS record associated with the domain being validated. The private key must be used to sign a message containing: a unique identifier for the CA, the domain name\(s\) in the certificate, a timestamp, and a hash of the public key in the certificate. This message may be hashed and then have the signature generated over the hash of this message. Obtaining such a signed message from a certificate applicant authorizes the CA specified in the message to sign a certificate for those domain names with the specified public key within 24h of the timestamp provided in the message. The CA MUST retrieve the public key or a hash of the public key corresponding to the private key used for signing the message via an authenticated DNS lookup using either authenticated channels to the relevant authoritative nameservers (e.g., DoH or DoT) or validation of a DNSSEC signature chain back to the ICANN root. After private key control is established, the CA MUST additionally perform a validation method that is compliant with the Baseline Requirements for the Issuance and Management of Publicly‐Trusted TLS Server Certificates.



In the event that **no "methods" property specified in the top-level property\_list,** all methods specified in this document are acceptable as well as cryptographic domain validation defined in future RFCs. Future RFCs MAY specify additional methods for cryptographic domain validation so long as they satisfy the properties of cryptographic domain validation \(i.e., robust against global man-in-the-middle adversaries\).


# Permissible Options

The following options MAY used as parameters in the "options" or "options-critical" property in the top-level property\_list.

1. **mpic-full-quorum:** This option specifies a CA MUST perform multi-perspective-issuace-corroboration and only proceed with validation if all perspectives corroborate the primary domain validation determination.

2. **mpic-n-1-quorum:** This option specifies a CA MUST perform multi-perspective-issuace-corroboration and only proceed with validation if all perspectives except for max 1 corroborate the primary domain validation determination.

3. **mpic-count-\<N\>:** This option specifies a CA MUST perform multi-perspective-issuace-corroboration and use a minimum of N perspectives where N is an integer value.

# Applicability

\"security\" CAA tags can be used on domains that are contained in both domain validation certificates \(where only the domain name in a certificate is validated\) and extended or organization validated certificates \(where information like organization identity as well as domain name is validated\). Cryptographic Domain Validation only hardens the security of the validation of domain names, not broader identities \(e.g., organization names\). The use of cryptographic domain validation in an OV or EV certificate only improves the validation of the domain name\(s\) contained in the certificate \(in the common name or subject-alternate names fields\) and does not impact the validation of other forms of identity contained in the certificate. Use of cryptographic domain validation in a DV certificate does not imply validation of any identity beyond the domain name\(s\) in the certificate.


# Security Considerations

Many of the security considerations regarding \"security\" CAA records are inherited from those of CAA records more generally. Because \"security\" CAA records do not introduce any new methods for validating domain ownership, they do not increase the attack surface of fraudulent validations. \"security\" CAA records reduce the attack surface of fraudulent validations by limiting which validation methods may be used and thus eliminating the risk posed by less-secure validation methods. Particularly, domains without a \"security\" CAA record are often highly vulnerable to man-in-the-middle adversaries that can intercept communications from a CA to the victim's domain. This record significantly reduces this attack surface.

As with any restriction on certificate issuance, this introduces the potential for a Denial of Service attack (or DoS attack). There are two potential approaches to launching a DoS attack via \"security\" CAA records. The first is to attack a domain and spoof the existence of a \"security\" CAA record in order to prevent the domain owner from renewing his or her certificate \(presuming the domain under attack was not using a validation method compliant with the \"security\" CAA record\). This attack vector is not novel to \"security\" CAA records and is enabled solely by following RFC 6844 alone. Per RFC 6844, the presence of any not-understood CAA record with the critical flag prevents issuance. Thus, the adoption of \"security\" CAA records does not increase the attack surface for this form of DoS attack as a gibberish CAA record with the critical flag set could enable this type of attack as well.

A second approach to a DoS attack enabled by \"security\" CAA records is to target a domain already using a \"security\" CAA record and interfere with all of the permitted validation methods with the idea that the presence of the \"security\" CAA will prevent the domain from falling back on alternative validation methods. This attack vector is mitigated by the diversity of different methods available to domain owners for validating domain ownership using \"security\" CAA records. A domain owner may use an alternate method to satisfy the \"security\" CAA record. In the event that a domain owner truly cannot satisfy any cryptographic domain validation method, the domain owner can still mitigate this attack by removing the \"security\" CAA record, obtaining a certificate, and then reinstating the \"security\" CAA record once the attack is over. As with all CAA records, CAs should not cache stale CAA record lookups that block issuance and should instead recheck the CAA record set when a new issuance request is received.

Furthermore, beyond the cryptographic assurances offered by these methods, options that control a CA’s MPIC behavior provide the option for additional defense in depth. Should an adversary compromise the cryptographic credentials of a domain (e.g., an ACME account private key), the adversary may be able to forge cryptographic domain validation. As an additional layer of defense, domains may use the MPIC related options to stipulate a more secure MPIC behavior by the issuing CA reducing the chance of being victim to a man-in-the-middle attack on validation in such a scenario.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
