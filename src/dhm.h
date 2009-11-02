/**
 * \file dhm.h
 */
#ifndef _DHM_H
#define _DHM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_DHM_READ_PARAMS_FAILED      0x0700
#define ERR_DHM_MAKE_PARAMS_FAILED      0x0720
#define ERR_DHM_READ_PUBLIC_FAILED      0x0740
#define ERR_DHM_MAKE_PUBLIC_FAILED      0x0760
#define ERR_DHM_CALC_SECRET_FAILED      0x0780

#include "bignum.h"

typedef struct
{
    int len;    /*!<  size(P) in chars  */
    mpi P;      /*!<  prime modulus     */
    mpi G;      /*!<  generator         */
    mpi X;      /*!<  secret value      */
    mpi GX;     /*!<  self = G^X mod P  */
    mpi GY;     /*!<  peer = G^Y mod P  */
    mpi K;      /*!<  key = GY^X mod P  */
    mpi RP;     /*!<  recalc R*R mod P  */
}
dhm_context;

/**
 * \brief          Parse the ServerKeyExchange parameters
 *
 * \param ctx      DHM context
 * \param p        &(start of input buffer)
 * \param end      end of buffer
 *
 * \return         0 if successful, or ERR_DHM_READ_PARAMS_FAILED
 */
int dhm_ssl_read_params( dhm_context *ctx, uchar **p, uchar *end );

/**
 * \brief          Setup and write the ServerKeyExchange parameters
 *
 * \param ctx      DHM context
 * \param output   destination buffer
 * \param olen     number of chars written
 * \param rng_fn   points to the RNG function
 * \param rng_st   points to the RNG state
 *
 * \return         0 if successful, or an MPI error code
 */
int dhm_ssl_make_params( dhm_context *ctx, uchar *output, int *olen,
                         ulong (*rng_fn)(void *), void *rng_st );

/**
 * \brief          Import the peer's public value (G^Y)
 *
 * \param ctx      DHM context
 * \param input    input buffer
 * \param ilen     size of buffer
 *
 * \return         0 if successful, or ERR_DHM_READ_PUBLIC_FAILED
 */
int dhm_read_public( dhm_context *ctx, uchar *input, int ilen );

/**
 * \brief          Create private value X and export G^X
 *
 * \param ctx      DHM context
 * \param output   destination buffer
 * \param olen     must be == ctx->P.len
 * \param rng_fn   points to the RNG function
 * \param rng_st   points to the RNG state
 *
 * \return         0 if successful, or ERR_DHM_MAKE_PUBLIC_FAILED
 */
int dhm_make_public( dhm_context *ctx, uchar *output, int olen,
                     ulong (*rng_fn)(void *), void *rng_st );

/**
 * \brief          Derive and export the shared secret (G^Y)^X mod P
 *
 * \param ctx      DHM context
 * \param output   destination buffer
 * \param olen     must be == ctx->P.len
 *
 * \return         0 if successful, or ERR_DHM_MAKE_PUBLIC_FAILED
 */
int dhm_calc_secret( dhm_context *ctx, uchar *output, int olen );

/*
 * \brief          Free the components of a DHM key
 */
void dhm_free( dhm_context *ctx );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int dhm_self_test( void );

#ifdef __cplusplus
}
#endif

#endif
