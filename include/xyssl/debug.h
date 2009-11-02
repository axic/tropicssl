/**
 * \file debug.h
 */
#ifndef SSL_DEBUG_H
#define SSL_DEBUG_H

#include "xyssl/config.h"
#include "xyssl/bignum.h"
#include "xyssl/x509.h"

#if defined(XYSSL_DEBUG_MSG)

#define SSL_DEBUG_MSG( level, args )                    \
    do {                                                \
        if( ssl->debuglvl >= level )                    \
            debug_print_msg( __FILE__, __LINE__,        \
                             debug_format_msg args );   \
    } while( 0 )

#define SSL_DEBUG_RET( level, msg, ret )                \
    do {                                                \
        if( ssl->debuglvl >= level )                    \
            debug_print_ret( __FILE__, __LINE__,        \
                           msg, ret );                  \
    } while( 0 )

#define SSL_DEBUG_BUF( level, msg, buf, len )           \
    do {                                                \
        if( ssl->debuglvl >= level )                    \
            debug_print_buf( __FILE__, __LINE__,        \
                           msg, buf, len );             \
    } while( 0 )

#define SSL_DEBUG_MPI( level, msg, X )                  \
    do {                                                \
        if( ssl->debuglvl >= level )                    \
            debug_print_mpi( __FILE__, __LINE__,        \
                           msg, X );                    \
    } while( 0 )

#define SSL_DEBUG_CRT( level, msg, crt )                \
    do {                                                \
        if( ssl->debuglvl >= level )                    \
            debug_print_crt( __FILE__, __LINE__,        \
                           msg, crt );                  \
    } while( 0 )

#else

#define SSL_DEBUG_MSG( level, args )           do { } while( 0 )
#define SSL_DEBUG_RET( level, msg, ret )       do { } while( 0 )
#define SSL_DEBUG_BUF( level, msg, buf, len )  do { } while( 0 )
#define SSL_DEBUG_MPI( level, msg, X )         do { } while( 0 )
#define SSL_DEBUG_CRT( level, msg, crt )       do { } while( 0 )

#endif

#ifdef __cplusplus
extern "C" {
#endif

char *debug_format_msg( const char *format, ... );
void debug_print_msg( char *file, int line, char *msg );
void debug_print_ret( char *file, int line, char *msg, int ret );
void debug_print_buf( char *file, int line, char *msg,
                      unsigned char *buf, int len );
void debug_print_mpi( char *file, int line, char *msg, mpi *X );
void debug_print_crt( char *file, int line, char *msg, x509_cert *crt );

#ifdef __cplusplus
}
#endif

#endif /* debug.h */
