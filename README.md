# McCrypto

As with everything in the @doctormckay namespace on npm, this is mostly for my own usage. If you want to use it that's
fine, but don't expect any support. I'll respect semver so you don't need to worry about breaking changes if you
pin your dependencies properly.

This is just a module that uses node's built-in `crypto` module. The idea is to make it easier to encrypt stuff
and store it on disk or send it over the wire securely.

See [here](https://github.com/DoctorMcKay/node-crypto/blob/master/index.js#L3) for the supported ciphers.

# Methods

### isWellFormed(buffer)
- `buffer` - A `Buffer` object

Returns `true` if the input buffer is a well-formed blob which can be decrypted by this module.

### encrypt(cipher, key, data)
- `cipher` - One of the Cipher constants
- `key` - Either a string or a `Buffer` containing your encryption key
- `data` - Either a string (interpreted as UTF-8) or a `Buffer` containing the plaintext you want to encrypt

Returns a `Buffer` containing the encrypted contents. The output should be interpreted as a black box, but for reference
here is the structure:

- `magic` - A 2-byte magic value
- `flags` - A 1-byte bitstring of flags
- `cipher` - A 1-byte value containing the cipher constant

All remaining data is left up to the specific cipher.

- `AES256CTR`
    - `ivLength` - A 1-byte value containing the length of the IV
    - `iv` - The randomly-generated binary IV (length given by `ivLength`)
    - `ciphertext` - The encrypted ciphertext
- `AES256CTRWithHMAC`
    - `ivLength` - A 1-byte value containing the length of the IV
    - `iv` - The randomly-generated binary IV (length given by `ivLength`)
    - `ciphertext` - The encrypted ciphertext
    - `hmac` - The HMAC (20 bytes)

The `key` may be interpreted differently depending on the cipher.

- `AES256CTR` - The key is hashed with SHA256 and the binary hash is used as the key
- `AES256CTRWithHMAC` - Same as above

### decrypt(key, data[, expectAuthentication])
- `key` - Either a string or a `Buffer` containing your encryption key (should match what was given to encrypt())
- `data` - A `Buffer` containing your encrypted data (should be identical to what was returned by encrypt())
- `expectAuthentication` - Optional. If `true`, this will throw an `Error` if the data is not authenticated (e.g. with HMAC)

Decrypts a buffer and returns the plaintext. If you originally passed a string to `encrypt()`, this will return a
UTF-8 string. Otherwise, it will return a `Buffer`.
