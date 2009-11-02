/*
 *  The RSA Public-Key cryptosystem
 *
 *  Copyright (C) 2006-2007  Christophe Devine
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
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "xyssl/rsa.h"

#if !defined(NO_GENPRIME)
/*
 * Generate an RSA keypair
 */
int rsa_gen_key( rsa_context *ctx, int nbits, int exponent,
                 int (*rng_f)(void *), void *rng_d )
{
    int ret;
    mpi P1, Q1, H, G;

    if( nbits < 128 || exponent < 3 || rng_f == NULL )
        return( ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1, &Q1, &H, &G, NULL );

    memset( ctx, 0, sizeof( rsa_context ) );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    CHK( mpi_lset( &ctx->E, exponent ) );

    nbits >>= 1;

    do
    {
        CHK( mpi_gen_prime( &ctx->P, nbits, 0, rng_f, rng_d ) );
        CHK( mpi_gen_prime( &ctx->Q, nbits, 0, rng_f, rng_d ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &P1, &Q1, &H, &G, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}
#endif

/*
 * Perform an RSA public key operation
 */
int rsa_public( rsa_context   *ctx,
                unsigned char *input,  int ilen,
                unsigned char *output, int olen )
{
    int ret;
    mpi T;

    if( ilen != ctx->len || olen != ctx->len )
        return( ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &T, NULL );

    CHK( mpi_read_binary( &T, input, ilen ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( ERR_RSA_BAD_INPUT_DATA );
    }

    CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    CHK( mpi_write_binary( &T, output, &olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Perform an RSA private key operation
 */
int rsa_private( rsa_context   *ctx,
                 unsigned char *input,  int ilen,
                 unsigned char *output, int olen )
{
    int ret;
    mpi T, T1, T2;

    if( ilen != ctx->len || olen != ctx->len )
        return( ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &T, &T1, &T2, NULL );

    CHK( mpi_read_binary( &T, input, ilen ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( ERR_RSA_BAD_INPUT_DATA );
    }

#if 0
    CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif

    CHK( mpi_write_binary( &T, output, &olen ) );

cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Check if the public key is valid
 */
int rsa_check_pubkey( rsa_context *ctx )
{
    if( ( ctx->N.p[0] & 1 ) == 0 || 
        ( ctx->E.p[0] & 1 ) == 0 )
        return( ERR_RSA_KEY_CHK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > 4096 )
        return( ERR_RSA_KEY_CHK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( ERR_RSA_KEY_CHK_FAILED );

    return( 0 );
}

/*
 * Check if the private key is valid
 */
int rsa_check_privkey( rsa_context *ctx )
{
    int ret = 0;
    mpi TN, P1, Q1, H, G;

    mpi_init( &TN, &P1, &Q1, &H, &G, NULL );

    CHK( mpi_mul_mpi( &TN, &ctx->P, &ctx->Q ) );
    CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    if( mpi_cmp_mpi( &TN, &ctx->N ) == 0 &&
        mpi_cmp_int( &G, 1 ) == 0 )
    {
        mpi_free( &TN, &P1, &Q1, &H, &G, NULL );
        return( 0 );
    }

cleanup:

    mpi_free( &TN, &P1, &Q1, &H, &G, NULL );
    return( ERR_RSA_KEY_CHK_FAILED | ret );
}

/*
 * Add the PKCS#1 v1.5 padding and do a public RSA
 */
int rsa_pkcs1_encrypt( rsa_context   *ctx,
                       unsigned char *input,  int ilen,
                       unsigned char *output, int olen )
{
    int nb_pad;
    unsigned char *p = output;

    if( olen != ctx->len || olen < ilen + 11 )
        return( ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    *p++ = RSA_CRYPT;

    while( nb_pad-- > 0 )
    {
        do { *p = rand(); } while( *p == 0 );
        p++;
    }

    *p++ = 0;
    memcpy( p, input, ilen );

    return( rsa_public( ctx, output, olen, output, olen ) );
}

/*
 * Do a private RSA, removes the PKCS#1 v1.5 padding
 */
int rsa_pkcs1_decrypt( rsa_context   *ctx,
                       unsigned char *input,  int  ilen,
                       unsigned char *output, int *olen )
{
    int ret;
    unsigned char *p, buf[512];

    if( ilen != ctx->len || ilen < 16 || ilen > 512 )
        return( ERR_RSA_BAD_INPUT_DATA );

    if( ( ret = rsa_private( ctx, input, ilen, buf, ilen ) ) != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 || *p++ != RSA_CRYPT )
        return( ERR_RSA_INVALID_PADDING );

    while( *p != 0 )
    {
        if( p >= buf + ilen - 1 )
            return( ERR_RSA_INVALID_PADDING );
        p++;
    }
    p++;

    if( *olen < ilen - (int)(p - buf) )
        return( ERR_RSA_INVALID_PADDING );

    *olen = ilen - (int)(p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Perform a private RSA to sign a message digest
 */
int rsa_pkcs1_sign( rsa_context   *ctx,  int alg_id,
                    unsigned char *hash, int hashlen,
                    unsigned char *sig,  int siglen )
{
    int nb_pad;
    unsigned char *p = sig;

    if( siglen != ctx->len || siglen < 16 )
        return( ERR_RSA_BAD_INPUT_DATA );

    switch( alg_id )
    {
        case RSA_RAW:
            nb_pad = siglen - 3 - hashlen;
            break;

        case RSA_MD2:
        case RSA_MD4:
        case RSA_MD5:
            nb_pad = siglen - 3 - 34;
            break;

        case RSA_SHA1:
            nb_pad = siglen - 3 - 35;
            break;

        default:
            return( ERR_RSA_BAD_INPUT_DATA );
    }

    if( nb_pad < 8 )
        return( ERR_RSA_BAD_INPUT_DATA );

    *p++ = 0;
    *p++ = RSA_SIGN;

    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    switch( alg_id )
    {
        case RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        default:
            return( ERR_RSA_BAD_INPUT_DATA );
    }

    return( rsa_private( ctx, sig, siglen, sig, siglen ) );
}

/*
 * Perform a public RSA and check the message digest
 */
int rsa_pkcs1_verify( rsa_context   *ctx,  int alg_id,
                      unsigned char *hash, int hashlen,
                      unsigned char *sig,  int siglen )
{
    int ret, len;
    unsigned char *p, c, buf[512];

    if( siglen != ctx->len || siglen < 16 || siglen > 512 )
        return( ERR_RSA_BAD_INPUT_DATA );

    if( ( ret = rsa_public( ctx, sig, siglen, buf, siglen ) ) != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 || *p++ != RSA_SIGN )
        return( ERR_RSA_INVALID_PADDING );

    while( *p != 0 )
    {
        if( p >= buf + siglen - 1 || *p != 0xFF )
            return( ERR_RSA_INVALID_PADDING );
        p++;
    }
    p++;

    len = siglen - (int)( p - buf );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && alg_id == RSA_MD2 ) ||
            ( c == 4 && alg_id == RSA_MD4 ) ||
            ( c == 5 && alg_id == RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 ) 
                return( 0 );
            else
                return( ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && alg_id == RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
            memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( ERR_RSA_VERIFY_FAILED );
    }

    if( len == hashlen && alg_id == RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( ERR_RSA_VERIFY_FAILED );
    }

    return( ERR_RSA_INVALID_PADDING );
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->N,  &ctx->E,  &ctx->D,
              &ctx->P,  &ctx->Q,  &ctx->DP,
              &ctx->DQ, &ctx->QP, &ctx->RN,
              &ctx->RP, &ctx->RQ, NULL );
}

#if defined(SELF_TEST)

#include "xyssl/sha1.h"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

/*
 * Checkup routine
 */
int rsa_self_test( int verbose )
{
    int len;
    rsa_context rsa;
    unsigned char sha1sum[20];
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];

    memset( &rsa, 0, sizeof( rsa ) );

    rsa.len = KEY_LEN;
    mpi_read_string( &rsa.N , 16, RSA_N  );
    mpi_read_string( &rsa.E , 16, RSA_E  );
    mpi_read_string( &rsa.D , 16, RSA_D  );
    mpi_read_string( &rsa.P , 16, RSA_P  );
    mpi_read_string( &rsa.Q , 16, RSA_Q  );
    mpi_read_string( &rsa.DP, 16, RSA_DP );
    mpi_read_string( &rsa.DQ, 16, RSA_DQ );
    mpi_read_string( &rsa.QP, 16, RSA_QP );

    if( verbose != 0 )
        printf( "  RSA key validation: " );

    if( rsa_check_pubkey(  &rsa ) != 0 ||
        rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( rsa_pkcs1_encrypt( &rsa, rsa_plaintext,  PT_LEN,
                                 rsa_ciphertext, KEY_LEN ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 decryption : " );

    len = sizeof( rsa_decrypted );

    if( rsa_pkcs1_decrypt( &rsa, rsa_ciphertext, KEY_LEN,
                                 rsa_decrypted,  &len ) != 0 ||
        memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 data sign  : " );

    sha1( rsa_plaintext, PT_LEN, sha1sum );

    if( rsa_pkcs1_sign( &rsa, RSA_SHA1, sha1sum, 20,
                        rsa_ciphertext, KEY_LEN ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsa, RSA_SHA1, sha1sum, 20,
                          rsa_ciphertext, KEY_LEN ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n\n" );

    rsa_free( &rsa );

    return( 0 );
}
#else
int rsa_self_test( int verbose )
{
    return( 0 );
}
#endif
