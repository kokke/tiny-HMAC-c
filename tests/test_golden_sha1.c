#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sha1.h"



static void calculate_sha1(const uint8_t* msg, unsigned nbytes, uint8_t* output)
{
  struct sha1 ctx;

  sha1_reset(&ctx);
  sha1_input(&ctx, msg, nbytes);
  sha1_result(&ctx, output);
}

static void test_hash(const uint8_t* msg, unsigned len, const uint8_t* digest_expected)
{
  uint8_t digest[20];
  uint8_t digest_hex[40];
  size_t i;

  for (i = 0; i < sizeof(digest); ++i)
  {
    digest[i] = 0;
  }

  calculate_sha1(msg, len, digest);

  printf("  SHA1('%s') = '", msg);
  for (i = 0; i < sizeof(digest); ++i)
  {
    sprintf((char*)digest_hex + (2 * i), "%.02x", digest[i]);
    printf("%.02x", digest[i]);
  }
  printf("'\n");

  for (i = 0; i < sizeof(digest_hex); ++i)
  {
    assert(digest_hex[i] == digest_expected[i]);
  }
}



typedef struct
{
  const uint8_t* input;
  const uint8_t* output;
} regression_test_t;


const regression_test_t tests[] =
{
  { (uint8_t*) "The quick brown fox jumps over the lazy dog",
    (uint8_t*) "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"     },
  
   { (uint8_t*) "The quick brown fox jumps over the lazy cog",
    (uint8_t*) "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"     },
  
  { (uint8_t*) "",
    (uint8_t*) "da39a3ee5e6b4b0d3255bfef95601890afd80709"     },

  { (uint8_t*) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    (uint8_t*) "84983e441c3bd26ebaae4aa1f95129e5e54670f1"     },

  { (uint8_t*) "abc",
    (uint8_t*) "a9993e364706816aba3e25717850c26c9cd0d89d"     },

  { (uint8_t*) "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    (uint8_t*) "a49b2446a02c645bf419f995b67091253a04a259"     },

};


int main()
{
  int ntests = sizeof(tests) / sizeof(*tests);

  printf("\nRunning %u golden tests.\n\n", ntests);

  const uint8_t* msg_input;
  const uint8_t* hash_output;
  uint32_t msg_length;

  int i;
  for (i = 0; i < ntests; ++i)
  {
    msg_input   = tests[i].input;
    hash_output = tests[i].output;
    msg_length  = strlen((const char*)msg_input);

    test_hash(msg_input, msg_length, hash_output);
  }

  printf("\n\n");

  return 0;
}


