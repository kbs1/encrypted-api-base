# Encrypted API
Encrypted API packages provide secure and authenticated communication between two applications over the internet. Two shared secrets are used,
one for encryption and decryption using `aes-256-ctr`, other for checksumming the data using `sha512-hmac`. All request and response data
between applications are transmitted securely (encrypted). Each request and response is valid for maximally 10 seconds.

Server implementations ([Laravel](https://github.com/kbs1/encrypted-api-server-laravel), [PHP](https://github.com/kbs1/encrypted-api-server-php))
support replay attacks protection and IPv4 whitelisting. Multiple calling applications are supported.
Each calling application has it's own set of shared secrets. This distinguishes and authenticates each calling application on the server side, and makes
sure no caller is able to read any service response or send any service request except of their own.

HTTPS is not a requirement in this screnario, but is recommended.

Client implementations ([PHP](https://github.com/kbs1/encrypted-api-client-php), [NodeJS](https://github.com/kbs1/encrypted-api-client-nodejs)) provide
a convenient way to call any Encrypted API service. Each client verifies the server response to make sure it is valid and not tampered with.

The setup as a whole protects using MITM attacks, authenticates both the server and the caller, and offers protection against replay attacks, all over
plain HTTP, or HTTPS.

This repository contains base (shared) implementations of encryptor and decryptor and is not meant to be used separately.
