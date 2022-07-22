#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha1.h"
#include "hmac.h"


static void check_num_args(int argc, char** argv);
static void check_format_args(char** argv, const uint32_t key_len, const uint32_t msg_len, const uint32_t output_len);
static void copy_input_args(char** argv, const uint32_t key_len, const uint32_t msg_len, const uint32_t output_len, uint8_t* key, uint8_t* msg, uint8_t* expected);
static void compare_output_with_expected(const uint8_t* actual, const uint8_t* expected);


/*
 *
 *  Read from STDIN: 
 *  ----------------
 *
 *     argv[1]   key                string in hex-format
 *     argv[2]   msg                string in hex-format
 *     argv[3]   expected-output    string in hex format
 *
 *  Convert 'key', 'msg' to binary and calculate HMAC_SHA1(key, msg).
 *
 *  Compare with expected-output and assert equality.
 *
 *
 */
int main(int argc, char* argv[])
{
  uint8_t key_bin[1024];
  uint8_t msg_bin[1024];
  uint8_t expected_bin[20];
  uint8_t hmac_bin[20];
  uint32_t key_len;
  uint32_t msg_len;
  uint32_t output_len;  

  /* Is number of input arguments in stdin correct? */
  check_num_args(argc, argv);

  /* Get length of input and expected-output argument */
  key_len = strlen(argv[1]);
  msg_len = strlen(argv[2]);
  output_len = strlen(argv[3]);

  /* Check that length of string-arguments are correct */
  check_format_args(argv, key_len, msg_len, output_len);

  /* Copy and convert input and expected-output from hex-string to binary */
  copy_input_args(argv, key_len, msg_len, output_len, key_bin, msg_bin, expected_bin);

  /* Calculate SHA1 hash of input */
  //calculate_sha1(input_bin, (input_len / 2), digest_bin);
  hmac_sha1(key_bin, (key_len / 2), msg_bin, (msg_len / 2), hmac_bin);

  /* Compare HASH(input) to expected-output */
  compare_output_with_expected(hmac_bin, expected_bin);

  return 0;
}


/* BEGIN STATIC FUNCTIONS: */



/* Helper to ensure stdin input format is correct */
static void check_num_args(int argc, char** argv)
{
  /* Print usage info if not correct */
  if (argc < 4)
  {
    printf("\n\nUsage: %s [key] [msg] [expected_HMAC_output]\n\n", argv[0]);
    exit(1);
  }
}


/* Helper to ensure stdin input format is correct */
static void check_format_args(char** argv, const uint32_t key_len, const uint32_t msg_len, const uint32_t output_len)
{
  /* Get input and expected hash digest from STDIN */
  if ((key_len & 1) != 0)
  {
    printf("\n\nUsage: %s [key] [msg] [expected_HMAC_output]\n\n", argv[0]);
    printf("  key-string must be of even length \n");
    printf("  '%s' has length %u \n\n", argv[1], key_len);
    exit(2);
  }
  if ((msg_len & 1) != 0)
  {
    printf("\n\nUsage: %s [key] [msg] [expected_HMAC_output]\n\n", argv[0]);
    printf("  msg-string must be of even length \n");
    printf("  '%s' has length %u \n\n", argv[2], msg_len);
    exit(2);
  }
  /* Check if lengths of input-strings are odd */
  if ((output_len & 1) != 0)
  {
    printf("\n\nUsage: %s [key] [msg] [expected_HMAC_output]\n\n", argv[0]);
    printf("  expected-HMAC-output-string must be of even length \n");
    printf("  '%s' has length %u \n\n", argv[3], output_len);
    exit(3);
  }
  /* Check if expected SHA1 digest hex-string is 40 byte long (20 byte / 160 bit hash) */
  if (output_len != 40)
  {
    printf("\n\nUsage: %s [input] [expected_output]\n\n", argv[0]);
    printf("  expected-HMAC-output-string must 40 bytes long \n");
    printf("  '%s' has length %u \n\n", argv[3], output_len);
    exit(4);
  }
}


/* Helper to convert and copy from hex-string to binary array */
static void copy_input_args(char** argv, const uint32_t key_len, const uint32_t msg_len, const uint32_t output_len, uint8_t* key, uint8_t* msg, uint8_t* expected)
{
  uint32_t i;
  for (i = 0; i < (key_len / 2); ++i)
  {
    sscanf(&argv[1][2 * i], "%2hhx", &key[i]);
  }

  for (i = 0; i < (msg_len / 2); ++i)
  {
    sscanf(&argv[2][2 * i], "%2hhx", &msg[i]);
  }

  for (i = 0; i < 20; ++i)
  {
    sscanf(&argv[3][2 * i], "%2hhx", &expected[i]);
    if ((2 * i) >= output_len)
    {
      break;
    }
  }
}


/* Comparison function: This is the test function */
static void compare_output_with_expected(const uint8_t* actual, const uint8_t* expected)
{
  uint32_t i;
  for (i = 0; i < 20; ++i)
  {
    assert(actual[i] == expected[i]);
  }
}





