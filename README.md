![CI](https://github.com/kokke/tiny-HMAC-c/actions/workflows/c-cpp.yml/badge.svg)

### Tiny HMAC in C

This is a small and portable implementation of the [HMAC algorithm](https://en.wikipedia.org/wiki/HMAC) written in C. 

This implementation only supports the [SHA-1 digest](https://en.wikipedia.org/wiki/SHA-1) currently.

Description from Wikipedia (emphasis added):

> In cryptography, an HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. **As with any MAC, it may be used to simultaneously verify both the data integrity and the authenticity of a message.**
> 
> **HMAC can provide message authentication using a shared secret instead of using digital signatures with asymmetric cryptography**. It trades off the need for a complex public key infrastructure by delegating the key exchange to the communicating parties, who are responsible for establishing and using a trusted channel to agree on the key prior to communication.

---

The API looks like this (I am using C99 `<stdint.h>`-style annotated types):

```C
#define HMAC_SHA1_DIGEST_SIZE 20
#define HMAC_SHA1_BLOCK_SIZE  64

/***********************************************************************'
 * HMAC(K,m)      : HMAC SHA1
 * @param key     : secret key
 * @param keysize : key-length in bytes
 * @param msg     : msg to calculate HMAC over
 * @param msgsize : msg-length in bytes
 * @param output  : writeable buffer with at least 20 bytes available
 */
void hmac_sha1(const uint8_t* key, 
               const uint32_t keysize,
               const uint8_t* msg,
               const uint32_t msgsize,
                     uint8_t* output);
```
