/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef PORTABLE_BLAKE2_H
#define PORTABLE_BLAKE2_H

#include <argon2.h>

#if defined(__cplusplus)
extern "C" {
#endif

 enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

#pragma pack(push, 1)
  typedef struct __blake2s_param
  {
    uint8_t  digest_length; 	/* 1 */
    uint8_t  key_length;    	/* 2 */
    uint8_t  fanout;        	/* 3 */
    uint8_t  depth;         	/* 4 */
    uint32_t leaf_length;   	/* 8 */
    uint8_t  node_offset[6];	/* 14 */
    uint8_t  node_depth;    	/* 15 */
    uint8_t  inner_length;  	/* 16 */
    /*uint8_t  reserved[0];*/
    uint8_t  salt[BLAKE2S_SALTBYTES]; /* 24 */
    uint8_t  personal[BLAKE2S_PERSONALBYTES];  /* 32 */
  } blake2s_param;

  typedef struct __blake2s_state
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[2 * BLAKE2S_BLOCKBYTES];
    uint32_t buflen;
    uint8_t  outlen;
    uint8_t  last_node;
  } blake2s_state;                   

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert 
enum {
    blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
    blake2_size_check_2 =
        1 / !!(sizeof(blake2s_param) == sizeof(uint64_t) * CHAR_BIT) 
};*/

/* Streaming API */
ARGON2_LOCAL int blake2s_init(blake2s_state *S, size_t outlen );
ARGON2_LOCAL int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen );
ARGON2_LOCAL int blake2s_init_param( blake2s_state *S, const blake2s_param *P );
ARGON2_LOCAL int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
ARGON2_LOCAL int blake2s_final( blake2s_state *S, void *out, size_t outlen );

/* Simple API */
ARGON2_LOCAL int blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

/* Argon2 Team - Begin Code */
ARGON2_LOCAL int blake2s_long(void *out, size_t outlen, const void *in, size_t inlen);
/* Argon2 Team - End Code */

#if defined(__cplusplus)
}
#endif

#endif
