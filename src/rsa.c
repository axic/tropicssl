/*
 *  The RSA PK cryptosystem
 *
 *  Copyright (C) 2006  Christophe Devine
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

#include "rsa.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"

/*
 * Generate a RSA keypair of nbits in size according
 * to the specified public exponent.
 *
 * Function "rng_func" takes one argument (rng_state)
 * and should return a random unsigned long.
 *
 * Returns 0 if successful, or ERR_RSA_KEYGEN_FAILED.
 */
int rsa_gen_key( rsa_context *ctx, uint nbits, uint exponent,
                 ulong (*rng_func)(void *), void *rng_state )
{
    int ret;
    mpi P1, Q1, H, G;

    mpi_init( &P1, &Q1, &H, &G, NULL );

    memset( ctx, 0, sizeof( rsa_context ) );

    /*
     * find primes P and Q with Q < P so that
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        CHK( mpi_gen_prime( &ctx->P, nbits / 2, 0,
                            rng_func, rng_state ) );

        CHK( mpi_gen_prime( &ctx->Q, nbits / 2, 0,
                            rng_func, rng_state ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

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

    ctx->len = nbits / 8;

cleanup:

    mpi_free( &P1, &Q1, &H, &G, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( ERR_RSA_KEYGEN_FAILED | ret );
    }

    return( 0 );   
}

/*
 * Perform an RSA public key operation. This function
 * does not take care of message padding: both ilen and
 * olen must be equal to the modulus size (ctx->len).
 *
 * Returns 0 if successful, or ERR_RSA_PUBLIC_FAILED.
 */
int rsa_public( rsa_context *ctx, uchar *input,  uint ilen,
                                  uchar *output, uint olen )
{
    int ret;
    mpi T;

    if( ilen != ctx->len || olen != ctx->len )
        return( ERR_RSA_PUBLIC_FAILED );

    mpi_init( &T, NULL );

    CHK( mpi_import( &T, input, ilen ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( ERR_RSA_PUBLIC_FAILED );
    }

    CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N ) );
    CHK( mpi_export( &T, output, &olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Perform an RSA private key operation. This function
 * does not take care of message padding: both ilen an
 * olen must be equal to the modulus size (ctx->len).
 *
 * Returns 0 if successful, or ERR_RSA_PRIVATE_FAILED.
 */
int rsa_private( rsa_context *ctx, uchar *input,  uint ilen,
                                   uchar *output, uint olen )
{
    int ret;
    mpi T, T1, T2;

    if( ilen != ctx->len || olen != ctx->len )
        return( ERR_RSA_PRIVATE_FAILED );

    mpi_init( &T, &T1, &T2, NULL );

    CHK( mpi_import( &T, input, ilen ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( ERR_RSA_PRIVATE_FAILED );
    }

#if 0
    CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P ) );
    CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q ) );

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

    CHK( mpi_export( &T, output, &olen ) );

cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Returns 0 if the public key is valid,
 * or ERR_RSA_KEY_CHECK_FAILED.
 */
int rsa_check_pubkey( rsa_context *ctx )
{
    if( ( ctx->N.p[0] & 1 ) == 0 || 
        ( ctx->E.p[0] & 1 ) == 0 )
        return( ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_size( &ctx->N ) < 128 ||
        mpi_size( &ctx->N ) > 4096 )
        return( ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_size( &ctx->E ) < 2 ||
        mpi_size( &ctx->E ) > 64 )
        return( ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Returns 0 if the private key is valid,
 * or ERR_RSA_KEY_CHECK_FAILED.
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
    return( ERR_RSA_KEY_CHECK_FAILED | ret );
}

/*
 * Add the PKCS1 v1.5 padding and perform a public RSA.
 *
 *      ctx     points to an RSA public key
 *      input   buffer holding the data to be encrypted
 *      ilen    length of the plaintext; cannot be longer
 *              than the modulus, minus 3+8 for padding
 *      output  buffer that will hold the ciphertext
 *      olen    must be the same as the modulus size
 *              (for example, 128 if RSA-1024 is used)
 *
 * Returns 0 if successful, or ERR_RSA_ENCRYPT_FAILED
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       uchar *input,  uint ilen,
                       uchar *output, uint olen )
{
    int nb_pad;
    uchar *p = output;

    if( olen != ctx->len || olen < ilen + 11 )
        return( ERR_RSA_ENCRYPT_FAILED );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    *p++ = RSA_CRYPT;

    while( nb_pad-- > 0 )
    {
        do { *p = (uchar) rand(); } while( *p == 0 );
        p++;
    }

    *p++ = 0;
    memcpy( p, input, ilen );

    if( rsa_public( ctx, output, olen, output, olen ) != 0 )
        return( ERR_RSA_ENCRYPT_FAILED );

    return( 0 );
}

/*
 * Perform a private RSA and remove the PKCS1 v1.5 padding.
 *
 *      ctx     points to an RSA private key
 *      input   buffer holding the encrypted data
 *      ilen    must be the same as the modulus size
 *      output  buffer that will hold the plaintext
 *      olen    size of output buffer, will be updated
 *              to contain the length of the plaintext
 *
 * Returns 0 if successful, or ERR_RSA_DECRYPT_FAILED
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       uchar *input,  uint  ilen,
                       uchar *output, uint *olen )
{
    uchar *p, tmp[512];

    if( ilen != ctx->len || ilen < 48 || ilen > 512 )
        return( ERR_RSA_DECRYPT_FAILED );

    if( rsa_private( ctx, input, ilen, tmp, ilen ) != 0 )
        return( ERR_RSA_DECRYPT_FAILED );

    p = tmp;

    if( *p++ != 0 || *p++ != RSA_CRYPT )
        return( ERR_RSA_DECRYPT_FAILED );

    while( *p != 0 )
    {
        if( p >= tmp + ilen - 1 )
            return( ERR_RSA_DECRYPT_FAILED );
        p++;
    }
    p++;

    if( *olen < ilen - (uint)(p - tmp) )
        return( ERR_RSA_DECRYPT_FAILED );

    *olen = ilen - (uint)(p - tmp);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Hash a message and perform a private RSA.
 *
 *      ctx     points to an RSA private key
 *      alg     must be set to RSA_MD2/4/5 or RSA_SHA1
 *      buf     buffer holding the data to be hashed
 *      buflen  length of the data
 *      sig     buffer that will hold the ciphertext
 *      siglen  must be the same as the modulus size
 *              (for example, 128 if RSA-1024 is used)
 *
 * Returns 0 if successful, or ERR_RSA_SIGN_FAILED
 */
int rsa_pkcs1_sign( rsa_context *ctx, int alg,
                    uchar *buf, uint buflen,
                    uchar *sig, uint siglen )
{
    int nb_pad;
    uchar *p = sig;

    if( siglen != ctx->len || siglen < 48 )
        return( ERR_RSA_SIGN_FAILED );

    switch( alg )
    {
        case RSA_MD2:
        case RSA_MD4:
        case RSA_MD5:
            nb_pad = siglen - 3 - 34;
            break;

        case RSA_SHA1:
            nb_pad = siglen - 3 - 35;
            break;

        default:
            return( ERR_RSA_SIGN_FAILED );
    }

    if( nb_pad < 8 )
        return( ERR_RSA_SIGN_FAILED );

    *p++ = 0;
    *p++ = RSA_SIGN;

    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    switch( alg )
    {
        case RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            md2_csum( buf, buflen, p + 18 );
            p[13] = 2; p += 34;
            break;

        case RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            md4_csum( buf, buflen, p + 18 );
            p[13] = 4; p += 34;
            break;

        case RSA_MD5:

            memcpy( p, ASN1_HASH_MDX, 18 );
            md5_csum( buf, buflen, p + 18 );
            p[13] = 5; p += 34;
            break;

        case RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            sha1_csum( buf, buflen, p + 15 );
            p += 15;
            break;

        default:
            return( ERR_RSA_SIGN_FAILED );
    }

    if( rsa_private( ctx, sig, siglen, sig, siglen ) != 0 )
        return( ERR_RSA_SIGN_FAILED );

    return( 0 );
}

/*
 * Perform a public RSA and check the message digest.
 *
 *      ctx     points to an RSA public key
 *      alg     can be set to RSA_MD{2,4,5}, RSA_SHA1
 *              or 0 for all
 *      buf     buffer holding the data to be hashed
 *      buflen  length of the data
 *      sig     buffer holding the ciphertext
 *      siglen  must be the same as the modulus size
 *
 * Returns 0 if successful, or ERR_RSA_VERIFY_FAILED
 */
int rsa_pkcs1_verify( rsa_context *ctx, int alg,
                      uchar *buf, uint buflen,
                      uchar *sig, uint siglen )
{
    int len;
    uchar  c, hash[32];
    uchar *p, tmp[512];

    if( siglen != ctx->len || siglen < 48 || siglen > 512 )
        return( ERR_RSA_VERIFY_FAILED );

    if( rsa_public( ctx, sig, siglen, tmp, siglen ) != 0 )
        return( ERR_RSA_VERIFY_FAILED );

    p = tmp;

    if( *p++ != 0 || *p++ != RSA_SIGN )
        return( ERR_RSA_VERIFY_FAILED );

    while( *p != 0 )
    {
        if( p >= tmp + siglen - 1 || *p != 0xFF )
            return( ERR_RSA_VERIFY_FAILED );
        p++;
    }
    p++;

    memset( hash, 0, sizeof( hash ) );
    len =  siglen - (uint)( p - tmp );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( ERR_RSA_VERIFY_FAILED );

        if( c == 2 && ( alg == 0 || alg == RSA_MD2 ) )
            md2_csum( buf, buflen, hash );

        if( c == 4 && ( alg == 0 || alg == RSA_MD4 ) )
            md4_csum( buf, buflen, hash );

        if( c == 5 && ( alg == 0 || alg == RSA_MD5 ) )
            md5_csum( buf, buflen, hash );

        if( memcmp( hash, p + 18, 16 ) == 0 )
            return( 0 );
    }

    if( len == 35 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) != 0 )
            return( ERR_RSA_VERIFY_FAILED );

        if( alg == 0 || alg == RSA_SHA1 )
            sha1_csum( buf, buflen, hash );

        if( memcmp( hash, p + 15, 20 ) == 0 )
            return( 0 );
    }

    return( ERR_RSA_VERIFY_FAILED );
}

/*
 * Free the components of an RSA key.
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->N,  &ctx->E,  &ctx->D,
              &ctx->P,  &ctx->Q,  &ctx->DP,
              &ctx->DQ, &ctx->QP, NULL );
}

#ifdef SELF_TEST

uchar plaintext[] =
    "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
    "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD";

#define PTLEN   24
#define CTLEN  128

ulong rsa_rand_test( void *rng_state )
{
    rng_state = NULL;
    return( (ulong) rand() );
}

/*
 * Checkup routine
 */
int rsa_self_test( void )
{
    int ret;
    uint len;
    rsa_context rsa;
    uchar decrypted[PTLEN];
    uchar ciphertext[CTLEN];

    printf( "  RSA key generation: " );

    if( rsa_gen_key( &rsa, CTLEN * 8, 65537,
                     rsa_rand_test, NULL ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n  RSA key validation: " );

    if( rsa_check_pubkey(  &rsa ) != 0 ||
        rsa_check_privkey( &rsa ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n  PKCS#1 encryption : " );

    if( rsa_pkcs1_encrypt( &rsa, plaintext,  PTLEN,
                                 ciphertext, CTLEN ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n  PKCS#1 decryption : " );

    len = sizeof( decrypted );

    if( rsa_pkcs1_decrypt( &rsa, ciphertext, CTLEN,
                                 decrypted,  &len ) != 0 ||
        memcmp( decrypted, plaintext, len ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n  PKCS#1 signature  : " );

    if( (ret=rsa_pkcs1_sign( &rsa, RSA_MD5,
                        plaintext,  PTLEN,
                        ciphertext, CTLEN ) )!= 0 )
    {
        printf( "%x failed\n",ret );
        return( 1 );
    }

    printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsa, RSA_MD5,
                          plaintext,  PTLEN,
                          ciphertext, CTLEN ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n\n" );
    return( 0 );
}
#else
int rsa_self_test( void )
{
    printf( "RSA self-test not available\n\n" );
    return( 1 );
}
#endif
