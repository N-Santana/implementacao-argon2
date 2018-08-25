/*
   Argon2 reference source code package based on BLAKE2 reference source code
	 package - reference C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
	 with this software. If not, see 
	 <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

/*
		Este arquivo é recorte/adaptação do arquivo "blake2s-ref.c" disponível no repositório oficial do BLAKE2
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2.h"
#include "blake2-impl.h"

static const uint32_t blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const unsigned int blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static BLAKE2_INLINE void blake2s_set_lastnode(blake2s_state *S)
{
  S->f[1] = ~0U;
}

static BLAKE2_INLINE void blake2s_set_lastblock(blake2s_state *S)
{
  if (S->last_node) blake2s_set_lastnode(S);

  S->f[0] = ~0U;
}

static BLAKE2_INLINE void blake2s_increment_counter(blake2s_state *S, const uint32_t inc)
{
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

static BLAKE2_INLINE void blake2s_invalidate_state(blake2s_state *S) /*checar*/
{
	clear_internal_memory(S, sizeof(*S));      /* wipe */
  blake2s_set_lastblock(S); /* invalidate for further use */
}

static BLAKE2_INLINE void blake2s_init0(blake2s_state *S)
{
  memset(S, 0, sizeof(*S));  /*sizeof(blake2s_state)*/
	memcpy(S->h, blake2s_IV, sizeof(S->h)); 

  /* for( int i = 0; i < 8; ++i ) S->h[i] = blake2s_IV[i]; */

}

/* init2 xors IV with input parameter block */
int blake2s_init_param(blake2s_state *S, const blake2s_param *P)
{
	const unsigned int *p = (const unsigned int *)P; 
	/* uint32_t *p = ( uint32_t * )( P ); */
	unsigned int i;

	if (NULL == P || NULL == S) return -1;
 
  blake2s_init0(S);
  /* IV XOR ParamBlock */
  for(i = 0; i < 8; ++i ) S->h[i] ^= load32(&p[i]);

  S->outlen = P->digest_length;
  return 0;
}

/* Sequential blake2s initialization */

int blake2s_init( blake2s_state *S, size_t outlen )
{
  if ( ( !outlen ) || ( outlen > BLAKE2S_OUTBYTES ) ) return -1;

  const blake2s_param P =
  {
    outlen,
    0,
    1,
    1,
    0,
    {0},
    0,
    0,
    {0},
    {0}
  };
  return blake2s_init_param( S, &P );
}

int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen )
{
  if ( ( !outlen ) || ( outlen > BLAKE2S_OUTBYTES ) ) return -1;

  if ( ( !key ) || ( !keylen ) || keylen > BLAKE2S_KEYBYTES ) return -1;

  const blake2s_param P =
  {
    outlen,
    keylen,
    1,
    1,
    0,
    {0},
    0,
    0,
    {0},
    {0}
  };

  if (blake2s_init_param(S, &P) < 0) {	/*mdf(P -> &P)*/
	blake2s_invalidate_state(S);
	return -1;
  }

  {
    uint8_t block[BLAKE2S_BLOCKBYTES];
    memset(block, 0, BLAKE2S_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2s_update(S, block, BLAKE2S_BLOCKBYTES);
    /* Burn the key from stack */
    clear_internal_memory(block, BLAKE2S_BLOCKBYTES);	/*mdf(secure_zero_memory - > clear_internal_memory)*/
  }

  return 0;
}

static void blake2s_compress(blake2s_state *S, const uint8_t *block)	/*mdf (block[BLAKE2S_BLOCKBYTES] -> *block)*/
{
  uint32_t m[16];
  uint32_t v[16];
	unsigned int i, r;

  for (i = 0; i < 16; ++i)
    m[i] = load32(block + i * sizeof(m[i]));

  for (i = 0; i < 8; ++i)
    v[i] = S->h[i];

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = blake2s_IV[4] ^ S->t[0];
  v[13] = blake2s_IV[5] ^ S->t[1];
  v[14] = blake2s_IV[6] ^ S->f[0];
  v[15] = blake2s_IV[7] ^ S->f[1];

#define G(r,i,a,b,c,d) \
  do { \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = rotr32(d ^ a, 16); \
    c = c + d; \
    b = rotr32(b ^ c, 12); \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = rotr32(d ^ a, 8); \
    c = c + d; \
    b = rotr32(b ^ c, 7); \
  } while(0)

#define ROUND(r)  \
  do { \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

	for (r = 0; r < 10; ++r) {
        ROUND(r);
    }

  for(i = 0; i < 8; ++i)
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
}

int blake2s_update(blake2s_state *S, const void *in, size_t inlen)	/*mdf(*in(uint8_t -> void))*/
{
  if (inlen == 0) return 0;

  /* Sanity check */
  if (S == NULL || in == NULL) return -1;

  /* Is this a reused state? */
  if (S->f[0] != 0) return -1;  /*------------------------------ok*/

  while( inlen > 0 )
  {
    uint32_t left = S->buflen;
    uint32_t fill = 2 * BLAKE2S_BLOCKBYTES - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); /*Fill buffer*/
      S->buflen += fill;
      blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );
      blake2s_compress( S, S->buf ); /*Compress*/
      memcpy( S->buf, S->buf + BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES ); /* Shift buffer left*/
      S->buflen -= BLAKE2S_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else /*inlen <= fill*/
    {
      memcpy( S->buf + left, in, inlen );
      S->buflen += ( uint32_t ) inlen; /*Be lazy, do not compress*/
      in += inlen;
      inlen -= inlen;
    }
  }

  return 0;
}

int blake2s_final( blake2s_state *S, void *out, size_t outlen )
{
  uint8_t buffer[BLAKE2S_OUTBYTES];
  unsigned int i;

  /* Sanity checks */
  if (S == NULL || out == NULL || outlen < S->outlen) {
      return -1;
  }

  /* Is this a reused state? */
  if (S->f[0] != 0) {
      return -1;
  }

  if( S->buflen > BLAKE2S_BLOCKBYTES )
  {
    blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );
    blake2s_compress( S, S->buf );
    S->buflen -= BLAKE2S_BLOCKBYTES;
    memcpy( S->buf, S->buf + BLAKE2S_BLOCKBYTES, S->buflen );
  }

  blake2s_increment_counter( S, ( uint32_t )S->buflen );
  blake2s_set_lastblock( S );
  memset(S->buf + S->buflen, 0, 2 * BLAKE2S_BLOCKBYTES - S->buflen); /*Padding */

  for(i = 0; i < 8; ++i ) { /* Output full hash to temp buffer */
    store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );
  }

  memcpy(out, buffer, S->outlen);
  clear_internal_memory(buffer, sizeof(buffer));
  clear_internal_memory(S->buf, sizeof(S->buf));
  clear_internal_memory(S->h, sizeof(S->h));
  return 0;
}

int blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)
{
    blake2s_state S;
    int ret = -1;

    /* Verify parameters */
    if (NULL == in && inlen > 0) {
        goto fail;
    }

    if (NULL == out || outlen == 0 || outlen > BLAKE2S_OUTBYTES) {
        goto fail;
    }

    if ((NULL == key && keylen > 0) || keylen > BLAKE2S_KEYBYTES) {
        goto fail;
    }

    if (keylen > 0) {
        if (blake2s_init_key(&S, outlen, key, keylen) < 0) {
            goto fail;
        }
    } else {
        if (blake2s_init(&S, outlen) < 0) {
            goto fail;
        }
    }

    if (blake2s_update(&S, in, inlen) < 0) {
        goto fail;
    }
    ret = blake2s_final(&S, out, outlen);

fail:
    clear_internal_memory(&S, sizeof(S));
    return ret;
}

/* Argon2 Team - Begin Code */
int blake2s_long(void *pout, size_t outlen, const void *in, size_t inlen) {
    uint8_t *out = (uint8_t *)pout;
    blake2s_state blake_state;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};
    int ret = -1;

    if (outlen > UINT32_MAX) {
        goto fail;
    }

    /* Ensure little-endian byte order! */
    store32(outlen_bytes, (uint32_t)outlen);

#define TRY(statement)                                                         \
    do {                                                                       \
        ret = statement;                                                       \
        if (ret < 0) {                                                         \
            goto fail;                                                         \
        }                                                                      \
    } while ((void)0, 0)

    if (outlen <= BLAKE2S_OUTBYTES) {
        TRY(blake2s_init(&blake_state, outlen));
        TRY(blake2s_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
        TRY(blake2s_update(&blake_state, in, inlen));
        TRY(blake2s_final(&blake_state, out, outlen));
    } else {
        uint32_t toproduce;
        uint8_t out_buffer[BLAKE2S_OUTBYTES];
        uint8_t in_buffer[BLAKE2S_OUTBYTES];
        TRY(blake2s_init(&blake_state, BLAKE2S_OUTBYTES));
        TRY(blake2s_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
        TRY(blake2s_update(&blake_state, in, inlen));
        TRY(blake2s_final(&blake_state, out_buffer, BLAKE2S_OUTBYTES));
        memcpy(out, out_buffer, BLAKE2S_OUTBYTES / 2);
        out += BLAKE2S_OUTBYTES / 2;
        toproduce = (uint32_t)outlen - BLAKE2S_OUTBYTES / 2;

        while (toproduce > BLAKE2S_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2S_OUTBYTES);
            TRY(blake2s(out_buffer, BLAKE2S_OUTBYTES, in_buffer,
                        BLAKE2S_OUTBYTES, NULL, 0));
            memcpy(out, out_buffer, BLAKE2S_OUTBYTES / 2);
            out += BLAKE2S_OUTBYTES / 2;
            toproduce -= BLAKE2S_OUTBYTES / 2;
        }

        memcpy(in_buffer, out_buffer, BLAKE2S_OUTBYTES);
        TRY(blake2s(out_buffer, toproduce, in_buffer, BLAKE2S_OUTBYTES, NULL,
                    0));
        memcpy(out, out_buffer, toproduce);
    }
fail:
    clear_internal_memory(&blake_state, sizeof(blake_state));
    return ret;
#undef TRY
}
/* Argon2 Team - End Code */
