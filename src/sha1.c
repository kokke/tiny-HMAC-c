/*
 *  sha1.c
 *
 *  Description:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1, produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 * Caveats:
 *     SHA-1 is designed to work with messages less than 2^64 bits
 *     long.  Although SHA-1 allows a message digest to be generated
 *     for messages of any number of bits less than 2^64, this
 *     implementation only works with messages with a length that is
 *     a multiple of the size of an 8-bit character.
 *
 */

#include "sha1.h"

/* Local Function Prototyptes */
static void     _pad_block(struct sha1*);
static void     _process_block(struct sha1*);

/* SHA1 circular left shift */
static uint32_t _circular_shift(const uint32_t nbits, const uint32_t word)
{
  return ((word << nbits) | (word >> (32 - nbits)));
}

/*
 * sha1_reset
 *
 * Description:
 *     This function will initialize the SHA1-context in preparation
 *     for computing a new SHA1 message digest.
 *
 * Parameters:
 *     context: [in/out]
 *         The context to reset.
 *
 * Returns:
 *     sha Error Code.
 *
 */
int sha1_reset(struct sha1* context)
{
  if (context == 0)
  {
    return shaNull;
  }

  context->Length_Low           = 0;
  context->Length_High          = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0] = 0x67452301;
  context->Intermediate_Hash[1] = 0xEFCDAB89;
  context->Intermediate_Hash[2] = 0x98BADCFE;
  context->Intermediate_Hash[3] = 0x10325476;
  context->Intermediate_Hash[4] = 0xC3D2E1F0;

  context->flags = 0;

  return shaSuccess;
}

/*
 * sha1_result
 *
 * Description:
 *     This function will return the 160-bit message digest into the
 *     Message_Digest array  provided by the caller.
 *     NOTE: The first octet of hash is stored in the 0th element,
 *           the last octet of hash in the 19th element.
 *
 * Parameters:
 *     context: [in/out]
 *         The context to use to calculate the SHA-1 hash.
 *     Message_Digest: [out]
 *         Where the digest is returned.
 *
 * Returns:
 *     sha Error Code.
 *
 */
int sha1_result(struct sha1* context, uint8_t Message_Digest[SHA1HashSize])
{
  int i;

  if (    (context == 0)
       || (Message_Digest == 0))
  {
    return shaNull;
  }

  if ((context->flags & FLAG_CORRUPTED) != 0)
  {
    return shaStateError;
  }

  if ((context->flags & FLAG_COMPUTED) == 0)
  {
    _pad_block(context);

    for (i = 0; i < 64; ++i)
    {
      /* message may be sensitive, clear it out */
      context->Message_Block[i] = 0;
    }
    context->Length_Low = 0;    /* and clear length */
    context->Length_High = 0;
    context->flags |= FLAG_COMPUTED;
  }

  for (i = 0; i < SHA1HashSize; ++i)
  {
    Message_Digest[i] = (context->Intermediate_Hash[i >> 2] >> (8 * (3 - (i & 0x03))));
  }

  return shaSuccess;
}

/*
 *  sha1_input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int sha1_input(struct sha1* context, const uint8_t* message_array, unsigned length)
{
  if (length == 0)
  {
    return shaSuccess;
  }

  if (    (context == 0)
       || (message_array == 0))
  {
    return shaNull;
  }

  if ((context->flags & FLAG_COMPUTED) != 0)
  {
    context->flags |= FLAG_CORRUPTED;
    return shaStateError;
  }

  if ((context->flags & FLAG_CORRUPTED) != 0)
  {
    return shaStateError;
  }

  while (    (length != 0)
          && (context->flags == 0))
  {
    context->Message_Block[context->Message_Block_Index] = (*message_array);

    context->Message_Block_Index += 1;
    context->Length_Low += 8;

    if (context->Length_Low == 0)
    {
      context->Length_High += 1;

      if (context->Length_High == 0)
      {
        /* Message is too long */
        context->flags |= FLAG_CORRUPTED;
      }
    }

    if (context->Message_Block_Index == 64)
    {
      _process_block(context);
    }

    message_array += 1;
    length -= 1;
  }

  return shaSuccess;
}

/*
 *  _process_block
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:

 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 *
 *
 */
#if 0 // original code
static void _process_block(struct sha1 *context)
{
  const uint32_t K[] = /* Constants defined in SHA-1 */
  {
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
  };
  uint32_t t;                 /* Loop counter                */
  uint32_t temp;              /* Temporary word value        */
  uint32_t W[80];             /* Word sequence               */
  uint32_t A, B, C, D, E;     /* Word buffers                */

  /*
   *  Initialize the first 16 words in the array W
   */
  for (t = 0; t < 16; ++t)
  {
    W[t]  = context->Message_Block[(t * 4) + 0] << 24;
    W[t] |= context->Message_Block[(t * 4) + 1] << 16;
    W[t] |= context->Message_Block[(t * 4) + 2] << 8;
    W[t] |= context->Message_Block[(t * 4) + 3] << 0;
  }

  for (t = 16; t < 80; ++t)
  {
    W[t] = _circular_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
  }

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for (t = 0; t < 20; ++t)
  {
    temp =  _circular_shift(5, A) +
            ((B & C) | ((~B) & D)) + E + W[t] + K[0];
    E = D;
    D = C;
    C = _circular_shift(30, B);
    B = A;
    A = temp;
  }

  for (; t < 40; ++t)
  {
    temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = _circular_shift(30, B);
    B = A;
    A = temp;
  }

  for (; t < 60; ++t)
  {
    temp = _circular_shift(5, A) +
           ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
    E = D;
    D = C;
    C = _circular_shift(30, B);
    B = A;
    A = temp;
  }

  for (; t < 80; ++t)
  {
    temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = _circular_shift(30, B);
    B = A;
    A = temp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;

  context->Message_Block_Index = 0;
}

#else

//#define METHOD2
  void _process_block(struct sha1 *context)
  {
    const uint32_t K[] =             /* Constants defined in SHA-1 */
    {
      0x5A827999,
      0x6ED9EBA1,
      0x8F1BBCDC,
      0xCA62C1D6
    };
    uint8_t       t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
#ifdef METHOD2
    uint8_t       s;
    uint32_t      W[16];
#else
    uint32_t      W[80];             /* Word sequence               */
#endif
    uint32_t      A, B, C, D, E;     /* Word buffers                */

   /*
    * Initialize the first 16 words in the array W
    */
   for (t = 0; t < 16; ++t)
   {
      W[t]  = ((uint32_t)context->Message_Block[t * 4 + 0]) << 24;
      W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
      W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
      W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]) << 0;
    }

#ifndef METHOD2
    for (t = 16; t < 80; ++t)
    {
      W[t] = _circular_shift(1, (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]));
    }
#endif

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for (t = 0; t < 20; ++t)
    {
#ifdef METHOD2
      s = t & 0x0f;
      if (t >= 16)
      {
	W[s] = _circular_shift(1, (W[(s + 13) & 0x0f] ^ W[(s + 8) & 0x0f] ^ W[(s + 2) & 0x0f] ^ W[s]));
      }
      temp =  _circular_shift(5, A) + ((B & C) | ((~B) & D)) + E + W[s] + K[0];
#else
      temp =  _circular_shift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
#endif
      E = D;
      D = C;
      C = _circular_shift(30, B);
      B = A;
      A = temp;
    }

    for (t = 20; t < 40; ++t)
    {
#ifdef METHOD2
      s = (t & 0x0f);
      W[s] = _circular_shift(1, (W[(s + 13) & 0x0f] ^ W[(s + 8) & 0x0f] ^ W[(s + 2) & 0x0f] ^ W[s]));
      temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[s] + K[1];
#else
      temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
#endif
      E = D;
      D = C;
      C = _circular_shift(30, B);
      B = A;
      A = temp;
    }

    for (t = 40; t < 60; ++t)
    {
#ifdef METHOD2
      s = (t & 0x0f);
      W[s] = _circular_shift(1, (W[(s + 13) & 0x0f] ^ W[(s + 8) & 0x0f] ^ W[(s + 2) & 0x0f] ^ W[s]));
      temp = _circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[s] + K[2];
#else
      temp = _circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
#endif
      E = D;
      D = C;
      C = _circular_shift(30, B);
      B = A;
      A = temp;
    }

    for (t = 60; t < 80; ++t)
    {
#ifdef METHOD2
      s = (t & 0x0f);
      W[s] = _circular_shift(1, (W[(s + 13) & 0x0f] ^ W[(s + 8) & 0x0f] ^ W[(s + 2) & 0x0f] ^ W[s]));
      temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[s] + K[3];
#else
      temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
#endif
      E = D;
      D = C;
      C = _circular_shift(30, B);
      B = A;
      A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
  }

#endif


/*
 *  _pad_block
 *
 * Description:
 *     According to the standard, the message must be padded to an even
 *     512 bits.  The first padding bit must be a '1'.  The last 64
 *     bits represent the length of the original message.  All bits in
 *     between should be 0.  This function will pad the message
 *     according to those rules by filling the Message_Block array
 *     accordingly.  It will also call the ProcessMessageBlock function
 *     provided appropriately.  When it returns, it can be assumed that
 *     the message digest has been computed.
 *
 * Parameters:
 *     context: [in/out]
 *         The context to pad
 *     ProcessMessageBlock: [in]
 *         The appropriate SHA*ProcessMessageBlock function
 * Returns:
 *     Nothing.
 *
 */
static void _pad_block(struct sha1* context)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index > 55)
  {
    context->Message_Block[context->Message_Block_Index] = 0x80;
    context->Message_Block_Index += 1;

    while (context->Message_Block_Index < 64)
    {
      context->Message_Block[context->Message_Block_Index] = 0;
      context->Message_Block_Index += 1;
    }

    _process_block(context);

    while (context->Message_Block_Index < 56)
    {
      context->Message_Block[context->Message_Block_Index] = 0;
      context->Message_Block_Index += 1;
    }
  }
  else
  {
    context->Message_Block[context->Message_Block_Index] = 0x80;
    context->Message_Block_Index += 1;

    while (context->Message_Block_Index < 56)
    {
      context->Message_Block[context->Message_Block_Index] = 0;
      context->Message_Block_Index += 1;
    }
  }

  /*
   * Store the message length as the last 8 bytes
   */
  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >>  8;
  context->Message_Block[59] = context->Length_High >>  0;
  context->Message_Block[60] = context->Length_Low  >> 24;
  context->Message_Block[61] = context->Length_Low  >> 16;
  context->Message_Block[62] = context->Length_Low  >>  8;
  context->Message_Block[63] = context->Length_Low  >>  0;

  _process_block(context);
}





