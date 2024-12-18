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
 -
    fullname: Grace Cimaszewski
    organization: Princeton University
    email: gcimaszewski@princeton.edu
 -
    fullname: Cyrill E. Krähenbühl
    organization: Princeton University
    email: cyrill.k@princeton.edu
 -
    fullname: Liang Wang
    organization: Princeton University
    email: lw19@princeton.edu
 -
    fullname: Aaron Gable
    organization: ISRG
    email: aaron@letsencrypt.org
 -
    fullname: Prateek Mittal
    organization: Princeton University
    email: pmittal@princeton.edu

normative:

    RFC5234:

    RFC8555:

    RFC8657:

    RFC8659:

informative:


--- abstract

Cryptographic domain validation procedures leverage authenticated communication channels to ensure resilience against attacks by both on-path and off-path network attackers which may be located between the CA and the network resources related to the domain contained in the certificate.
Domain owners can leverage "security" Property Tags specified in CAA records (defined in {{RFC8659}}) with the critical flag set, to ensure that CAs perform cryptographic domain validation during their issuance procedure, hence defending against global man-in-the-middle adversaries.
This document defines the syntax of the CAA security Property as well as acceptable means for cryptographic domain validation procedures.


--- middle

# Introduction

A CAA security Property Tag is compliant with {{RFC8659}} and puts restrictions on the circumstances under which a CA is allowed to sign a certificate for a given domain.
A security Property Tag on a domain implies that validation for this domain must be done in a manner that defends against network adversaries even if an adversary is capable of intercepting and/or modifying communication between the CA and the network resources related to the domain being validated.
Issuance of a certificate to a domain with a security Property Tag MUST follow one of the specified Cryptographic Domain Validation (CDV) methods outlined in this document or future extensions.
CDV methods MUST rely on cryptographic protocols (like DNSSEC or DoH/DoT) that offer security properties even in the presence of man-in-the-middle adversaries that can intercept any communication occurring over the public Internet.

Not all CDV methods are themselves compliant with the CA/Browser Forum's Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates.
Hence, any CDV method that does not meet the CA/Browser Forum Baseline Requirements for TLS server certificate issuance must be used in conjunction with such a compliant domain validation method.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# CAA security Property

The CAA security Property Tag MUST be "security" and the flags field of a CAA record containing the security Property MUST have the critical bit set.
In this document, we refer to a CAA record with these characteristics as a **security CAA record**.

The CAA security Property Value has the following sub-syntax (specified in ABNF as per {{RFC5234}}).

security-value = \*WSP \[attribute-list\] \*WSP

attribute-list = (attribute \*WSP "," \*WSP attribute-list) / attribute

attribute = attribute-name \*WSP \["(" \*WSP attribute-list \*WSP ")"\]

attribute-name = character-set *character-set

character-set = ALPHA / DIGIT / ":" / "_" / "-"

Hence, the security Property Value can either be empty or entirely whitespace, or contain a list of comma-separated attributes.
Each attribute has an optional list of comma-separated (sub-)attributes associated with the attribute in parentheses after the attribute.
These attributes can in turn be associated with sub-attributes, allowing the specification of nested attribute lists.
Attributes MUST consist only of lowercase letters (a-z), uppercase letters (A-Z), numbers (0-9), colon (:), underscore (_), and hyphen (-), and are case sensitive.

All attributes specified in an attribute-list MUST be unique.
An attribute-list MUST NOT have two attributes with the same name specified even if they contain different sub-attributes.
If sub-attributes are specified, the sub-attribute list MUST NOT be empty, i.e., "attribute()" is not a valid CAA security Property Value.

# Well-known Attributes

The top-level attribute-list MAY contain the following attributes.

1. **methods:** If specified, this attribute MUST have sub-attributes listing various cryptographic domain validation methods that can be used to validate that particular domain.
A CA MUST use one of the methods specified in the methods sub-attributes to perform cryptographic domain validation.
If there is no method specified that the CA is capable of complying with, the CA MUST deny issuance.

2. **options:** If specified, this attribute MUST have sub-attributes listing various options.
A CA SHOULD try to honor any option specified in this list.
If a CA does not understand an option or does not have that option implemented the, CA MAY proceed with issuance.

3. **options-critical:** If specified, this attribute MUST have sub-attributes listing various options.
To proceed with issuance, a CA MUST understand and implement all options specified in the options-critical sub-attributes

The top-level attribute-list MAY contain additional attributes and a CA MAY proceed with issuance even if it does not understand these additional attributes.
Subsequent RFCs MAY standardize additional attributes.

# Permissible Methods

The following attributes MAY be specified as sub-attributes of the methods attributes.
Each method specifies particular aspects of certificate issuance that MUST be satisfied for a certificate to be issued using that method.
While some methods entail the use of CA/Browser Forum-compliant domain control validation methods, others do not entail CA/Browser Forum-compliant domain control validation and must be used in conjunction with a CA/Browser Forum-compliant domain control validation method to permit certificate issuance.

1. **secure-dns-record-change:** This method involves an applicant showing control of a DNSSEC-protected DNS record or a record that was retrieved via a DoH or DoT tunnel to the relevant authoritative nameservers used in the DNS resolution.
This can be done via 1\) the validation method "DNS Change" specified in the CA/Browser Forum's Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates \(Section 3.2.2.4.7\) or 2\) the "dns-01" method of the ACME RFC {{RFC8555}}.
For this method to be satisfied, the FQDN where the DNS change is demonstrated MUST be protected by DNSSEC or lookups to the relevant authoritative nameservers MUST be conducted over authenticated channels \(e.g., DoH/DoT\).

2. **http-validation-over-tls:** This method involves the completion of an HTTP domain validation challenge over an HTTPS session using TCP port 443 where the server authenticates with an existing publicly-trusted valid certificate covering the domain in question.
The certificate cannot be self-signed or expired.
This method MAY be directly satisfied while a CA is performing the "Agreed-Upon Change to Website v2" domain control validation method specified in the the CA/Browser Forum's Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates \(Section 3.2.2.4.18\). The ACME "http-01" challenge specified in {{RFC8555}} does not permit the use of HTTPS or port 443 when a CA is contacting the domain in question.
A CA MAY still satisfy the **http-validation-over-tls** method even if it does not initiate connections to port 443 for HTTP challenges so long as either 1\) the connection initiated to port 80 serves a redirect to the same domain name over HTTPS at port 443 and the connection to the domain at port 443 servers a valid, trusted certificate or 2\) in addition to contacting the domain over port 80 the CA also contacts the domain over port 443 using HTTPS and the connection is established with a valid, trusted certificate and the same challenge value is observed.
Operators of security-critical domains MAY choose not to permit this method since, unlike other cryptographic domain validation methods specified in this document, its security relies on the non-existence of malicious certificates for a domain at time of the creation of the security Property Tag in the domain's policy.

3. **known-account-specifier:** For a CA to issue a certificate using this method 1) there MUST exist a unique identifier for a CA subscriber account that is communicated with the CA out-of-band, over authenticated DNS lookups, or in another manner that is immune to man-in-the-middle adversaries, and 2) the CA may only issue a certificate to an applicant that has authenticated itself to the CA as having access to that specified subscriber account.
A CA does not have permission to issue under this method unless both of these criteria are met.
Once these criteria have been met, the CA MUST additionally perform a validation method that is compliant with the Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates.
One acceptable way of including this account identifier is with the CAA ACME account URI extension, defined in {{RFC8657}}, in an authenticated DNS record.

4. **private-key-control:** This method involves an applicant showing control of a private key that corresponds to a public key placed in a DNS record associated with the domain being validated.
The private key must be used to sign a message containing: a unique identifier for the CA, the domain name\(s\) in the certificate, a timestamp, and a hash of the public key in the certificate.
This message may be hashed and then have the signature generated over the hash of this message.
Obtaining such a signed message from a certificate applicant authorizes the CA specified in the message to sign a certificate for those domain names with the specified public key within 24h of the timestamp provided in the message.
The CA MUST retrieve the public key or a hash of the public key corresponding to the private key used for signing the message via an authenticated DNS lookup using either authenticated channels to the relevant authoritative nameservers (e.g., DoH or DoT) or validation of a DNSSEC signature chain back to the ICANN root.
After private key control is established, the CA MUST additionally perform a validation method that is compliant with the Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates.

In the event that **no methods attribute is specified in the top-level attribute-list,** all methods specified in this document are acceptable as well as cryptographic domain validation methods defined in future RFCs.
Future RFCs MAY specify additional methods for cryptographic domain validation so long as they satisfy the properties of cryptographic domain validation (i.e., robustness against global man-in-the-middle adversaries).

# Permissible Options

The following options MAY used as sub-attributes in the options or options-critical attributes in the top-level attribute-list.

1. **authenticated-policy-retrieval:** This option signifies to a CA that it MUST retrieve a domain's CAA security Property and any associated domain-owner identity (e.g., identifiers used for known-account-specifier and private-key-control) using authenticated DNS lookups or other authenticated channels.
If a CA finds this option as a sub-attribute in the options-critical attribute and the CAA security Property was not retrieved using authenticated DNS lookups, the CA MUST NOT issue a certificate for that domain.

Additionally, a CA MAY choose to honor its own non-standardized options that do not need to be supported by other CAs or the IETF.
These options MUST be prefixed with "-\<ca_name>-" where ca\_name is the name of the CA that initially developed the option.

# Applicability

CAA security Property Tags can be used on domains that are contained in both domain validation certificates (where only the domain name in a certificate is validated) and extended or organization validated certificates (where information like organization identity as well as domain name is validated).
Cryptographic Domain Validation only hardens the security of the validation of domain names, not broader identities (e.g., organization names).
The use of cryptographic domain validation in an OV or EV certificate only improves the validation of the domain name(s) contained in the certificate (in the common name or subject-alternate names fields) and does not impact the validation of other forms of identity contained in the certificate.
Use of cryptographic domain validation in a DV certificate does not imply validation of any identity beyond the domain name(s) in the certificate.

# Single CAA security Property for Each Domain

A single domain MUST NOT have multiple security Property Tags specified.
A domain's entire cryptographic domain validation policy MUST be encoded into a single CAA security Property.
If a CA finds a domain that has multiple security Property Tags at the same FQDN, the CA MUST block issuance.

# CAA security Property Protection

A security CAA record SHOULD be protected with a valid DNSSEC signature chain going back to the ICANN DNSSEC root or hosted on authoritative DNS servers that CAs have authenticated communication channels with.
Any security CAA record not protected by such a signature MAY not benefit from the security properties outlined in this document.
If it is not possible to have a DNSSEC signature chain back to the ICANN root, security CAA records SHOULD alternately be hosted in an authoritative DNS resolver that supports recursive-to-authoritative DoT or DoH.
CAs SHOULD also require recursive-to-authoritative DoT or DoH communication (and not permit standard unencrypted DNS connections) for DNS providers that host security CAA records.
This prevents downgrade attacks where an adversary attempts to interfere with the establishment of a DoT or DoH encrypted channel and cause a fallback to unencrypted DNS over UDP or TCP.

Serving security CAA records over authenticated DNS channels or using authenticated DNS records (i.e., DNSSEC) is critical to the effectiveness of the records because a security CAA record not protected by authenticated DNS may be suppressed by an adversary that can manipulate DNS responses.
This could potentially allow the adversary to downgrade validation to use a low-security method and undermine the security properties of the security Property Tag.

# Security Considerations

Many of the security considerations regarding security CAA records are inherited from those of CAA records more generally.
Because security CAA records do not introduce any new methods for validating domain ownership, they do not increase the attack surface of fraudulent validations.
Security CAA records reduce the attack surface of fraudulent validations by limiting which validation methods may be used and thus eliminating the risk posed by less-secure validation methods.
Particularly, domains without a security CAA record are often highly vulnerable to man-in-the-middle adversaries that can intercept communications from a CA to the victim's domain.
This record significantly reduces this attack surface.

As with any restriction on certificate issuance, this introduces the potential for a Denial of Service attack (or DoS attack).
There are two potential approaches to launching a DoS attack via security CAA records.
The first is to attack a domain and spoof the existence of a security CAA record in order to prevent the domain owner from renewing his or her certificate (presuming the domain under attack was not using a validation method compliant with the security CAA record).
This attack vector is not novel to security CAA records and is enabled solely by following the procedure specified in {{RFC8659}}.
Per {{RFC8659}}, the presence of any not-understood CAA record with the critical flag prevents issuance.
Thus, the adoption of security CAA records does not increase the attack surface for this form of DoS attack as a gibberish CAA record with the critical flag set could lead to the same type of attack.

A second approach to a DoS attack enabled by security CAA records is to target a domain already using a security CAA record and interfere with all of the permitted validation methods with the idea that the presence of the security CAA will prevent the domain from falling back on alternative validation methods.
This attack vector is mitigated by the diversity of different methods available to domain owners for validating domain ownership using security CAA records.
A domain owner may use an alternate method to satisfy the security CAA record.
In the event that a domain owner truly cannot satisfy any cryptographic domain validation method, the domain owner can still mitigate this attack by removing the security CAA record, obtaining a certificate, and then reinstating the security CAA record once the attack is over.
As with all CAA records, CAs should not cache stale CAA record lookups that block issuance and should instead recheck the CAA record set when a new issuance request is received.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
