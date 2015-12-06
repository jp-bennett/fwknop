/*
 *****************************************************************************
 *
 * File:    fko_hmac.c
 *
 * Purpose: Provide HMAC support to SPA communications
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/

#include "hmac.h"
#ifdef HAVE_C_UNIT_TESTS
DECLARE_TEST_SUITE(hmac_test, "hmac functions test suite");
#endif
typedef struct {
    MD5Context ctx_inside;
    MD5Context ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_md5_ctx;

typedef struct {
    SHA1_INFO ctx_inside;
    SHA1_INFO ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha1_ctx;

typedef struct {
    SHA256_CTX ctx_inside;
    SHA256_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha256_ctx;

typedef struct {
    SHA384_CTX ctx_inside;
    SHA384_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha384_ctx;

typedef struct {
    SHA512_CTX ctx_inside;
    SHA512_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha512_ctx;

static void
pad_init(unsigned char *inner_pad, unsigned char *outer_pad,
        const unsigned char * const key, const int key_len)
{
    int i = 0;

    for (i=0; i < MAX_DIGEST_BLOCK_LEN && i < key_len; i++) {
        inner_pad[i] = key[i] ^ 0x36;
        outer_pad[i] = key[i] ^ 0x5c;
    }
    if(i < MAX_DIGEST_BLOCK_LEN)
    {
        while(i < MAX_DIGEST_BLOCK_LEN)
        {
            inner_pad[i] = 0x36;
            outer_pad[i] = 0x5c;
            i++;
        }
    }
    return;
}

/* Begin MD5 HMAC functions
*/
static void
hmac_md5_init(hmac_md5_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(MD5_BLOCK_LEN < key_len)
    {
        /* Calculate the digest of the key
        */
        md5(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, final_len);

    MD5Init(&ctx->ctx_inside);
    MD5Update(&ctx->ctx_inside, ctx->block_inner_pad, MD5_BLOCK_LEN);

    MD5Init(&ctx->ctx_outside);
    MD5Update(&ctx->ctx_outside, ctx->block_outer_pad, MD5_BLOCK_LEN);

    return;
}

static void
hmac_md5_update(hmac_md5_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    MD5Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_md5_final(hmac_md5_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[MD5_DIGEST_LEN];

    MD5Final(digest_inside, &ctx->ctx_inside);
    MD5Update(&ctx->ctx_outside, digest_inside, MD5_DIGEST_LEN);
    MD5Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_md5(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_md5_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_md5_init(&ctx, hmac_key, hmac_key_len);
    hmac_md5_update(&ctx, msg, msg_len);
    hmac_md5_final(&ctx, hmac);

    return;
}

/* Begin SHA1 HMAC functions
*/
static void
hmac_sha1_init(hmac_sha1_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA1_BLOCK_LEN < key_len)
    {
        /* Calculate the digest of the key
        */
        sha1(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, final_len);

    sha1_init(&ctx->ctx_inside);
    sha1_update(&ctx->ctx_inside, ctx->block_inner_pad, SHA1_BLOCK_LEN);

    sha1_init(&ctx->ctx_outside);
    sha1_update(&ctx->ctx_outside, ctx->block_outer_pad, SHA1_BLOCK_LEN);

    return;
}

static void
hmac_sha1_update(hmac_sha1_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    sha1_update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha1_final(hmac_sha1_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA1_DIGEST_LEN];

    sha1_final(digest_inside, &ctx->ctx_inside);
    sha1_update(&ctx->ctx_outside, digest_inside, SHA1_DIGEST_LEN);
    sha1_final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha1(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha1_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha1_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha1_update(&ctx, msg, msg_len);
    hmac_sha1_final(&ctx, hmac);

    return;
}

/* Begin SHA256 HMAC functions
*/
static void
hmac_sha256_init(hmac_sha256_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA256_BLOCK_LEN < key_len)
    {
        /* Calculate the digest of the key
        */
        sha256(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, final_len);

    SHA256_Init(&ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA256_BLOCK_LEN);

    SHA256_Init(&ctx->ctx_outside);
    SHA256_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA256_BLOCK_LEN);

    return;
}

static void
hmac_sha256_update(hmac_sha256_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA256_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA256_DIGEST_LEN];

    SHA256_Final(digest_inside, &ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_LEN);
    SHA256_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha256_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha256_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha256_update(&ctx, msg, msg_len);
    hmac_sha256_final(&ctx, hmac);

    return;
}

/* Begin SHA384 HMAC functions
*/
static void
hmac_sha384_init(hmac_sha384_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    int            final_len = key_len;

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    /* When we eventually support arbitrary key sizes, take the digest
     * of the key with: sha384(final_key, init_key, final_len);
    */
    memcpy(final_key, key, final_len);

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, final_len);

    SHA384_Init(&ctx->ctx_inside);
    SHA384_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA384_BLOCK_LEN);

    SHA384_Init(&ctx->ctx_outside);
    SHA384_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA384_BLOCK_LEN);

    return;
}

static void
hmac_sha384_update(hmac_sha384_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA384_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha384_final(hmac_sha384_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA384_DIGEST_LEN];

    SHA384_Final(digest_inside, &ctx->ctx_inside);
    SHA384_Update(&ctx->ctx_outside, digest_inside, SHA384_DIGEST_LEN);
    SHA384_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha384(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha384_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha384_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha384_update(&ctx, msg, msg_len);
    hmac_sha384_final(&ctx, hmac);

    return;
}

/* Begin SHA512 HMAC functions
*/
static void
hmac_sha512_init(hmac_sha512_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    int            final_len = key_len;

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    /* When we eventually support arbitrary key sizes, take the digest
     * of the key with: sha512(final_key, init_key, final_len);
    */
    memcpy(final_key, key, final_len);

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, final_len);

    SHA512_Init(&ctx->ctx_inside);
    SHA512_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA512_BLOCK_LEN);

    SHA512_Init(&ctx->ctx_outside);
    SHA512_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA512_BLOCK_LEN);

    return;
}

static void
hmac_sha512_update(hmac_sha512_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA512_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha512_final(hmac_sha512_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA512_DIGEST_LEN];

    SHA512_Final(digest_inside, &ctx->ctx_inside);
    SHA512_Update(&ctx->ctx_outside, digest_inside, SHA512_DIGEST_LEN);
    SHA512_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha512(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha512_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha512_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha512_update(&ctx, msg, msg_len);
    hmac_sha512_final(&ctx, hmac);

    return;
}

void
hmac_sha3_256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA3_256_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[2 * MAX_DIGEST_BLOCK_LEN + 1] = {0};
    unsigned char *padded_msg = malloc(msg_len + MAX_DIGEST_BLOCK_LEN + 1);

    int final_len = hmac_key_len;
    if(hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(final_key, hmac_key, final_len);
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA3_256_BLOCK_LEN);
    memcpy(padded_msg + SHA3_256_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    FIPS202_SHA3_256(padded_msg, strlen((char*)padded_msg), inner_hash);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA3_256_BLOCK_LEN);
    memcpy(padded_hash + SHA3_256_BLOCK_LEN, inner_hash, SHA3_256_DIGEST_LEN);

    //the outer hash is the final hmac
    FIPS202_SHA3_256(padded_hash, strlen((char*)padded_hash), hmac);

    free(padded_msg);
}

void
hmac_sha3_512(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA3_512_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA3_512_BLOCK_LEN + SHA3_512_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = malloc(msg_len + MAX_DIGEST_BLOCK_LEN + 1);

    int final_len = hmac_key_len;

    if(hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(final_key, hmac_key, final_len);
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA3_512_BLOCK_LEN);
    memcpy(padded_msg + SHA3_512_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    FIPS202_SHA3_512(padded_msg, msg_len + SHA3_512_BLOCK_LEN, inner_hash);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA3_512_BLOCK_LEN);
    memcpy(padded_hash + SHA3_512_BLOCK_LEN, inner_hash, SHA3_512_DIGEST_LEN);

    //the outer hash is the final hmac
    FIPS202_SHA3_512(padded_hash, strlen((char*)padded_hash), hmac);

    free(padded_msg);
}

#ifdef HAVE_C_UNIT_TESTS

DECLARE_UTEST(test_hmac_md5_1, "hmac_md5 test vector 1")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "Hi There");
    strcpy(expected_hmac, "9294727a3638bb1c13f48ef8158bfc9d");
    strcpy(hmac_key, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");

    hmac_md5(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, MD5_DIGEST_LEN) == 0);
    printf("output was: %s\n", hmac_txt);
}

DECLARE_UTEST(test_hmac_sha1_1, "hmac_sha1 test vector 1")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "Hi There");
    strcpy(expected_hmac, "b617318655057264e28bc0b6fb378c8ef146be00");
    strcpy(hmac_key, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");

    hmac_sha1(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, SHA1_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha3_256_1, "hmac_sha3_256 test vector 1")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "Hi There");
    strcpy(expected_hmac, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");
    strcpy(hmac_key, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");

    hmac_sha3_256(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, 64) == 0);
}

DECLARE_UTEST(test_hmac_sha3_512_1, "hmac_sha3_512 test vector 1")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "Hi There");
    strcpy(expected_hmac, "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e");
    strcpy(hmac_key, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");

    hmac_sha3_512(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, 128) == 0);
}
DECLARE_UTEST(test_hmac_sha3_256_2, "hmac_sha3_256 test vector 2")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "what do ya want for nothing?");
    strcpy(expected_hmac, "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5");
    strcpy(hmac_key, "Jefe");

    hmac_sha3_256(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, 64) == 0);
}

DECLARE_UTEST(test_hmac_sha3_512_2, "hmac_sha3_512 test vector 2")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac[1024] = {0};
    int i = 0;

    strcpy(msg, "what do ya want for nothing?");
    strcpy(expected_hmac, "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024");
    strcpy(hmac_key, "Jefe");

    hmac_sha3_512(msg, strlen(msg), (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac, 128) == 0);
}

int register_ts_hmac_test(void)
{
    ts_init(&TEST_SUITE(hmac_test), TEST_SUITE_DESCR(hmac_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_md5_1), UTEST_DESCR(test_hmac_md5_1));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha1_1), UTEST_DESCR(test_hmac_sha1_1));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_256_1), UTEST_DESCR(test_hmac_sha3_256_1));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_512_1), UTEST_DESCR(test_hmac_sha3_512_1));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_256_2), UTEST_DESCR(test_hmac_sha3_256_2));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_512_2), UTEST_DESCR(test_hmac_sha3_512_2));

    return register_ts(&TEST_SUITE(hmac_test));
}

#endif /* HAVE_C_UNIT_TESTS */

