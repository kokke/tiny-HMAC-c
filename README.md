# tiny-HMAC-c
Small portable HMAC in C

API:

```C
#define HMAC_SHA1_HASH_SIZE 20

/***********************************************************************'
 * HMAC(K,m)      : HMAC SHA1
 * @param key     : secret key
 * @param keysize : key-length ín bytes
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
