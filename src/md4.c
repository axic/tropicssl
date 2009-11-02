/*
 *  RFC 1186/1320 compliant MD4 implementation
 *
 *  Copyright (C) 2003-2006  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */
/*
 *  The MD4 algorithm was designed by Ron Rivest in 1990.
 *
 *  http://www.ietf.org/rfc/rfc1186.txt
 *  http://www.ietf.org/rfc/rfc1320.txt
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "md4.h"

/* 
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                    \
{                                               \
    (n) = ( (ulong) (b)[(i)    ]       )        \
        | ( (ulong) (b)[(i) + 1] <<  8 )        \
        | ( (ulong) (b)[(i) + 2] << 16 )        \
        | ( (ulong) (b)[(i) + 3] << 24 );       \
}
#endif
#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uchar) ( (n)       );       \
    (b)[(i) + 1] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uchar) ( (n) >> 24 );       \
}
#endif

/*
 * Core MD4 functions
 */
void md4_starts( md4_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}

void md4_process( md4_context *ctx, uchar data[64] )
{
    ulong X[16], A, B, C, D;

    GET_UINT32_LE( X[0],  data,  0 );
    GET_UINT32_LE( X[1],  data,  4 );
    GET_UINT32_LE( X[2],  data,  8 );
    GET_UINT32_LE( X[3],  data, 12 );
    GET_UINT32_LE( X[4],  data, 16 );
    GET_UINT32_LE( X[5],  data, 20 );
    GET_UINT32_LE( X[6],  data, 24 );
    GET_UINT32_LE( X[7],  data, 28 );
    GET_UINT32_LE( X[8],  data, 32 );
    GET_UINT32_LE( X[9],  data, 36 );
    GET_UINT32_LE( X[10], data, 40 );
    GET_UINT32_LE( X[11], data, 44 );
    GET_UINT32_LE( X[12], data, 48 );
    GET_UINT32_LE( X[13], data, 52 );
    GET_UINT32_LE( X[14], data, 56 );
    GET_UINT32_LE( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x, y, z) ((x & y) | ((~x) & z))
#define P(a,b,c,d,x,s) { a += F(b,c,d) + x; a = S(a,s); }

    P( A, B, C, D, X[ 0],  3 );
    P( D, A, B, C, X[ 1],  7 );
    P( C, D, A, B, X[ 2], 11 );
    P( B, C, D, A, X[ 3], 19 );
    P( A, B, C, D, X[ 4],  3 );
    P( D, A, B, C, X[ 5],  7 );
    P( C, D, A, B, X[ 6], 11 );
    P( B, C, D, A, X[ 7], 19 );
    P( A, B, C, D, X[ 8],  3 );
    P( D, A, B, C, X[ 9],  7 );
    P( C, D, A, B, X[10], 11 );
    P( B, C, D, A, X[11], 19 );
    P( A, B, C, D, X[12],  3 );
    P( D, A, B, C, X[13],  7 );
    P( C, D, A, B, X[14], 11 );
    P( B, C, D, A, X[15], 19 );

#undef P
#undef F

#define F(x,y,z) ((x & y) | (x & z) | (y & z))
#define P(a,b,c,d,x,s) { a += F(b,c,d) + x + 0x5A827999; a = S(a,s); }

    P( A, B, C, D, X[ 0],  3 );
    P( D, A, B, C, X[ 4],  5 );
    P( C, D, A, B, X[ 8],  9 );
    P( B, C, D, A, X[12], 13 );
    P( A, B, C, D, X[ 1],  3 );
    P( D, A, B, C, X[ 5],  5 );
    P( C, D, A, B, X[ 9],  9 );
    P( B, C, D, A, X[13], 13 );
    P( A, B, C, D, X[ 2],  3 );
    P( D, A, B, C, X[ 6],  5 );
    P( C, D, A, B, X[10],  9 );
    P( B, C, D, A, X[14], 13 );
    P( A, B, C, D, X[ 3],  3 );
    P( D, A, B, C, X[ 7],  5 );
    P( C, D, A, B, X[11],  9 );
    P( B, C, D, A, X[15], 13 );

#undef P
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define P(a,b,c,d,x,s) { a += F(b,c,d) + x + 0x6ED9EBA1; a = S(a,s); }

    P( A, B, C, D, X[ 0],  3 );
    P( D, A, B, C, X[ 8],  9 );
    P( C, D, A, B, X[ 4], 11 );
    P( B, C, D, A, X[12], 15 );
    P( A, B, C, D, X[ 2],  3 );
    P( D, A, B, C, X[10],  9 );
    P( C, D, A, B, X[ 6], 11 );
    P( B, C, D, A, X[14], 15 );
    P( A, B, C, D, X[ 1],  3 );
    P( D, A, B, C, X[ 9],  9 );
    P( C, D, A, B, X[ 5], 11 );
    P( B, C, D, A, X[13], 15 );
    P( A, B, C, D, X[ 3],  3 );
    P( D, A, B, C, X[11],  9 );
    P( C, D, A, B, X[ 7], 11 );
    P( B, C, D, A, X[15], 15 );

#undef F
#undef P

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

void md4_update( md4_context *ctx, uchar *input, uint length )
{
    ulong left, fill;

    if( ! length ) return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        md4_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 )
    {
        md4_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, length );
    }
}

static uchar md4_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md4_finish( md4_context *ctx, uchar digest[16] )
{
    ulong last, padn;
    ulong high, low;
    uchar msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  msglen, 0 );
    PUT_UINT32_LE( high, msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    md4_update( ctx, md4_padding, padn );
    md4_update( ctx, msglen, 8 );

    PUT_UINT32_LE( ctx->state[0], digest,  0 );
    PUT_UINT32_LE( ctx->state[1], digest,  4 );
    PUT_UINT32_LE( ctx->state[2], digest,  8 );
    PUT_UINT32_LE( ctx->state[3], digest, 12 );
}

/*
 * Output MD5(file contents), returns 0 if successful.
 */
int md4_file( char *filename, uchar digest[16] )
{
    FILE *f;
    size_t n;
    md4_context ctx;
    uchar buf[1024];

    if( ( f = fopen( filename, "rb" ) ) == NULL )
        return( 1 );

    md4_starts( &ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        md4_update( &ctx, buf, n );

    md4_finish( &ctx, digest );

    fclose( f );
    return( 0 );
}

/*
 * Output MD4(buf)
 */
void md4_csum( uchar *buf, uint buflen, uchar digest[16] )
{
    md4_context ctx;

    md4_starts( &ctx );
    md4_update( &ctx, buf, buflen );
    md4_finish( &ctx, digest );
}

/*
 * Output HMAC-MD4(buf,key)
 */
void md4_hmac( uchar *buf, uint buflen, uchar *key, uint keylen,
                uchar digest[16] )
{
    uint i;
    md4_context ctx;
    uchar k_ipad[64];
    uchar k_opad[64];
    uchar tmpbuf[16];

    memset( k_ipad, 0x36, 64 );
    memset( k_opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    md4_starts( &ctx );
    md4_update( &ctx, k_ipad, 64 );
    md4_update( &ctx, buf, buflen );
    md4_finish( &ctx, tmpbuf );

    md4_starts( &ctx );
    md4_update( &ctx, k_opad, 64 );
    md4_update( &ctx, tmpbuf, 16 );
    md4_finish( &ctx, digest );

    memset( k_ipad, 0, 64 );
    memset( k_opad, 0, 64 );
    memset( tmpbuf, 0, 16 );
    memset( &ctx, 0, sizeof( md4_context ) );
}

#ifdef SELF_TEST
/* 
 * RFC 1320 test vectors
 */
static char *md4_test_str[7] =
{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012" \
        "345678901234567890"
};

static uchar md4_test_sum[7][16] =
{
    { 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
      0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 },
    { 0xBD, 0xE5, 0x2C, 0xB3, 0x1D, 0xE3, 0x3E, 0x46,
      0x24, 0x5E, 0x05, 0xFB, 0xDB, 0xD6, 0xFB, 0x24 },
    { 0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52,
      0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6, 0x72, 0x9D },
    { 0xD9, 0x13, 0x0A, 0x81, 0x64, 0x54, 0x9F, 0xE8,
      0x18, 0x87, 0x48, 0x06, 0xE1, 0xC7, 0x01, 0x4B },
    { 0xD7, 0x9E, 0x1C, 0x30, 0x8A, 0xA5, 0xBB, 0xCD,
      0xEE, 0xA8, 0xED, 0x63, 0xDF, 0x41, 0x2D, 0xA9 },
    { 0x04, 0x3F, 0x85, 0x82, 0xF2, 0x41, 0xDB, 0x35,
      0x1C, 0xE6, 0x27, 0xE1, 0x53, 0xE7, 0xF0, 0xE4 },
    { 0xE3, 0x3B, 0x4D, 0xDC, 0x9C, 0x38, 0xF2, 0x19,
      0x9C, 0x3E, 0x7B, 0x16, 0x4F, 0xCC, 0x05, 0x36 }
};

/*
 * Checkup routine
 */
int md4_self_test( void )
{
    int i;
    uchar md4sum[16];

    for( i = 0; i < 7; i++ )
    {
        printf( "  MD4 test #%d: ", i + 1 );

        md4_csum( (uchar *) md4_test_str[i],
                    strlen( md4_test_str[i] ), md4sum );

        if( memcmp( md4sum, md4_test_sum[i], 16 ) != 0 )
        {
            printf( "failed\n" );
            return( 1 );
        }

        printf( "passed\n" );
    }

    printf( "\n" );
    return( 0 );
}
#else
int md4_self_test( void )
{
    printf( "MD4 self-test not available\n\n" );
    return( 1 );
}
#endif
