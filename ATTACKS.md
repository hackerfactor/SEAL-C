# Attacks against SEAL
Attacks and countermeasures.

## Impersonation
Anyone can generate a key pair.
Anyone can specify the domain.
Anyone can specify the user-id.
This means, anyone can make a signature that looks like it came from anywhere.

Mitigation:

The signature can only be validated by someone who receives the picture if the public key is in DNS.

If you create a signature that claims to be from my domain, it won't validate unless the public key is valid and tied to the domain. An impersonator cannot make a valid signature.

## Altered Time
For local signing, the time is as trustworthy as the person who inserted it. It is very easy to backdate or postdate a signature.

Mitigation:

1. The signer's domain is explicitly listed as being responsible for the signature. And a user at that domain may also be listed. Although the timestamp is as trustworthy as the signer, you explicitly know who signed it.
2. SEAL supports the use of a remote signer. If the signer is unrelated to the content and is widely used and trusted, then they have no reason to alter the timestamp. Moreover, a remote user cannot specify the time that is set by the remote signer.

