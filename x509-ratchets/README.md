# X.509 Ratcheting Constructs

Certificates are issued with:

 - A given public/private key pair,
 - A subject,
 - An issuer link (using a subject and optional Authority Key ID hash),
 - A serial number,
 - Various other fields we don't care about.

Rotation of certificates is easy if they're leaves (replace and restart),
about as easy if they're intermediates (sign a new one), but hard if
they're roots.

There are various theoretical ratcheting certificates (ab)using the above
certificate fields. We define them below. Key to their understanding is the
following though:

 - While certificates are added to the trust store, it is ultimate the
   associated key material that determines trust: two issuer certificates
   with the same subject but different public keys cannot validate the same
   child; only if the keys are the same can this occur.

## Cross-signed Ratchet

The most common. A new key pair is generated and signed by two CAs, resulting
in two certificates. These certificates have the same subject (but different
issuers and serial numbers), allowing certificates they sign to be trusted by
either root.

Process flow:

            -------------------
           | generate key pair |
            -------------------
               |            |
     --------------        --------------
    | generate CSR |      | generate CSR |
     --------------        --------------
             |                   |
        -----------         -----------
       | signed by |       | signed by |
       | root A    |       | root B    |
        -----------         -----------


Certificate hierarchy:

     --------                                            --------
    | root A |                                          | root B |
     --------                                            --------
       |                                                      |
     ----------------                            ----------------
    | intermediate A |  <- same key material -> | intermediate B |
     ----------------              |             ----------------
                                   |
                          -------------------
                         | leaf certificates |
                          -------------------


This results in two trust paths: either of root A or root B (or both) could
exist in the client's trust stores and the leaf certificate would validate
correctly.

This is thus a unifying ratchet; two separate trust paths now join into a
single one, by having leaf certificate's issuer field to point to two separate
paths and conditionally be validated based on which is present in the trust
store.

This construct is documented in several places:

 - https://letsencrypt.org/certificates/
 - https://scotthelme.co.uk/cross-signing-alternate-trust-paths-how-they-work/
 - https://security.stackexchange.com/questions/14043/what-is-the-use-of-cross-signing-certificates-in-x-509


## Reissuance Ratchet

The second most common type of ratchet scheme. In this scheme, the existing
key material is used to generate a new certificate.

While similar to the cross-signed ratchet, this one differs in that usually
the reissuance happens after the original certificate expires or is close
to expiration and is issued by the same common CA. In the event of a
self-signed certificate (e.g., a root certificate), this changes the contents
of the certificate (due to the new serial number) but allow existing
leaf signatures to still validate.

Process flow:

              -------------------
             | generate key pair | ---------------> ...
              -------------------                   ...
               |              |                     ...
     --------------           --------------        ...
    | generate CSR |   <->   | generate CSR |       ...
     --------------           --------------        ...
             |                    |                 ...
     ------------------      ------------------     ...
    | signed by issuer | -> | signed by issuer | -> ...
     ------------------      ------------------     ...


Certificate hierarchy:

                              ------
                  -----------| root |-------------
                 /            ------              \
                 |                                |
     ---------------                           ---------------
    | original cert | <- same key material -> | reissued cert |
     ---------------              |            ---------------
                                  |
                          -------------------
                         | leaf certificates |
                          -------------------


Note that while this again results in two trust paths, depending on which
intermediate certificate is presented and is still valid, only a single
trust path will be used. When a reissued certificate is a root certificate,
the issuance link is simply self-loop. But, in this case, note that both
certificates are valid issuers of each other!

This is thus an incrementing ratchet; the life cycle of an existing key is
extended into the future by issuing a new certificate with the same key
material from the existing authority.

## Combining the above

We can use the above to rotate roots to new keys and extend their lifetimes.

There's two main variants of this: a forward ratchet, wherein an old
certificate is used to bless new key material, and a backwards ratchet,
wherein a new certificate is used to bless old key material. Indeed, both of
these ratchets are independently used by Let's Encrypt in the aforementioned
chain of trust document!

 - The link from `DST Root CA X3` to `ISRG Root X1` is an example of a forward
   ratchet.
 - The link from `ISRG Root X1` to `R3` (which was originally signed by
   `DST Root CA X3`) is an example of a backwards ratchet.

# Limitations

The [Authority Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1)
field may contain either or both of the issuer's keyIdentifier (a hash
of the public key) or both the issuer's Subject and Serial Number fields.
Generating certificates with the latter enabled prevents building a proper
cross-signed chain without re-issuing for the same serial number, which is
generally frowned upon. In the strictest sense, when cross-signing from a
different CA, the intermediate could be reissued with the same serial number,
assuming no previous certificate was issued by that CA with that serial,
but this does not work for reissued self-signed roots (as these must contain
distinct serial numbers else we risk breaking various assumptions in browsers).
