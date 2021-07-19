#ifndef __HMAC_H__
#define __HMAC_H__

#include <stdint.h>
#include "sha1.h"

#define HMAC_SHA1_HASH_SIZE 20

void hmac_sha1(const uint8_t* key, const uint32_t keysize, const uint8_t* msg, const uint32_t msgsize, uint8_t* output);


#endif /* __HMAC_H__ */


