# Security policy

Do not put tokens, private keys, account seed material, production OIDC configuration,
or raw authentication/network logs in an issue or pull request. Remove exposed material
from the issuer and relay, then report the incident privately through GitHub's security
advisory page for this repository.

The public `DevelopmentFileStore` is plaintext and intended for development. Production
applications must provide a protected `SecureStore` with integrity, confidentiality,
atomic replacement, and exclusive ownership.
