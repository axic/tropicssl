/*
 *  Diffie-Hellman-Merkle key exchange
 *
 *  Copyright (C) 2007  Christophe Devine
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
 *  Reference:
 *
 *  http://www.cacr.math.uwaterloo.ca/hac/ (chapter 12)
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>

#include "dhm.h"

/*
 * defined by caller
 */
extern char *dhm_ext_modulus;
extern char *dhm_ext_generator;

/*
 * helper to validate the mpi size and import it
 */
int dhm_ssl_read_bignum( mpi *X, uchar **p, uchar *end )
{
    int ret, n;

    if( end - *p < 2 )
        return( ERR_DHM_READ_PARAMS_FAILED );

    n = ( (*p)[0] << 8 ) | (*p)[1];
    (*p) += 2;

    if( (int)( end - *p ) < n )
        return( ERR_DHM_READ_PARAMS_FAILED );

    if( ( ret = mpi_import( X, *p, n ) ) != 0 )
        return( ERR_DHM_READ_PARAMS_FAILED | ret );

    (*p) += n;

    return( 0 );
}

/*
 * Parse the ServerKeyExchange parameters
 */
int dhm_ssl_read_params( dhm_context *ctx, uchar **p, uchar *end )
{
    int ret, n;

    memset( ctx, 0, sizeof( dhm_context ) );

    if( ( ret = dhm_ssl_read_bignum( &ctx->P,  p, end ) ) != 0 ||
        ( ret = dhm_ssl_read_bignum( &ctx->G,  p, end ) ) != 0 ||
        ( ret = dhm_ssl_read_bignum( &ctx->GY, p, end ) ) != 0 )
        return( ret );

    ctx->len = ( mpi_size( &ctx->P ) + 7 ) >> 3;

    if( end - *p < 2 )
        return( ERR_DHM_READ_PARAMS_FAILED );

    n = ( (*p)[0] << 8 ) | (*p)[1];
    (*p) += 2;

    if( end != *p + n )
        return( ERR_DHM_READ_PARAMS_FAILED );

    return( 0 );
}

/*
 * Setup and write the ServerKeyExchange parameters
 */
int dhm_ssl_make_params( dhm_context *ctx, uchar *output, int *olen,
                         ulong (*rng_fn)(void *), void *rng_st )
{
    int i, ret;
    int n1, n2, n3;
    uchar *p = output;

    /*
     * public parameters must be defined by the caller
     */
    CHK( mpi_read( &ctx->P, dhm_ext_modulus  , 16 ) );
    CHK( mpi_read( &ctx->G, dhm_ext_generator, 16 ) );

    /*
     * generate X and calc GX = G^X mod P
     */
    CHK( mpi_grow( &ctx->X, ctx->P.n ) );
    for( i = 0; i < ctx->X.n; i++ )
        ctx->X.p[i] = rng_fn( rng_st );

    CHK( mpi_exp_mod( &ctx->GX, &ctx->G, &ctx->X,
                      &ctx->P , &ctx->RP ) );

    /*
     * export P, G, GX
     */
#define DHM_MPI_EXPORT(X,n)             \
    p[0] = (uchar)( n >> 8 );           \
    p[1] = (uchar)( n );                \
    CHK( mpi_export( X, p + 2, &n ) );  \
    p += 2 + n;

    n1 = ( mpi_size( &ctx->P  ) + 7 ) >> 3;
    n2 = ( mpi_size( &ctx->G  ) + 7 ) >> 3;
    n3 = ( mpi_size( &ctx->GX ) + 7 ) >> 3;

    DHM_MPI_EXPORT( &ctx->P , n1 );
    DHM_MPI_EXPORT( &ctx->G , n2 );
    DHM_MPI_EXPORT( &ctx->GX, n3 );

    *olen  = p - output;
    ctx->len = n1;

cleanup:

    if( ret != 0 )
        return( ret | ERR_DHM_MAKE_PARAMS_FAILED );

    return( 0 );
}

/*
 * Import the peer's public value (G^Y)
 */
int dhm_read_public( dhm_context *ctx, uchar *input, int ilen )
{
    int ret;

    if( ctx == NULL || ilen != ctx->len )
        return( ERR_DHM_READ_PUBLIC_FAILED );

    if( ( ret = mpi_import( &ctx->GY, input, ilen ) ) != 0 )
        return( ERR_DHM_READ_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Create own private (X) and public (G^X) values
 */
int dhm_make_public( dhm_context *ctx, uchar *output, int olen,
                     ulong (*rng_func)(void *), void *rng_state )
{
    int ret, i;

    if( olen != ctx->len )
        return( ERR_DHM_MAKE_PUBLIC_FAILED );

    CHK( mpi_grow( &ctx->X, ctx->P.n ) );

    for( i = 0; i < ctx->X.n; i++ )
        ctx->X.p[i] = rng_func( rng_state );

    CHK( mpi_exp_mod( &ctx->GX, &ctx->G, &ctx->X,
                      &ctx->P , &ctx->RP ) );

    CHK( mpi_export( &ctx->GX, output, &olen ) );

cleanup:

    if( ret != 0 )
        return( ERR_DHM_MAKE_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Derive and export the shared secret (G^Y)^X mod P
 */
int dhm_calc_secret( dhm_context *ctx, uchar *output, int olen )
{
    int ret;

    if( ctx == NULL || olen != ctx->len )
        return( ERR_DHM_CALC_SECRET_FAILED );

    CHK( mpi_exp_mod( &ctx->K, &ctx->GY, &ctx->X,
                      &ctx->P, &ctx->RP ) );

    CHK( mpi_export( &ctx->K, output, &olen ) );

cleanup:

    if( ret != 0 )
        return( ERR_DHM_CALC_SECRET_FAILED | ret );

    return( 0 );
}

/*
 * Free the components of a DHM key
 */
void dhm_free( dhm_context *ctx )
{
    mpi_free( &ctx->RP, &ctx->K, &ctx->GY,
              &ctx->GX, &ctx->X, &ctx->G, &ctx->P, NULL );    
}

/*
 * Checkup routine
 */
int dhm_self_test( void )
{
    return( 0 );
}
