/* 
 * Copyright (c) 2006-2007, Christophe Devine
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer
 *       in the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of the XySSL nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "xyssl/config.h"

#if defined(XYSSL_DEBUG_C)

#include "xyssl/debug.h"

#include <stdarg.h>
#include <stdlib.h>

static char text[256];

char *debug_format_msg( const char *format, ... )
{
    va_list argp;

    va_start( argp, format );
    vsprintf( text, format, argp );
    va_end( argp );

    return( text );
}

void debug_print_msg( char *file, int line, char *text )
{
    printf( "%s(%04d): %s\n", file, line, text );
}

void debug_print_ret( char *file, int line, char *text, int ret )
{
    printf( "%s(%04d): %s() returned %d (0x%x)\n",
            file, line, text, ret, ret );
}

void debug_print_buf( char *file, int line, char *text,
                    unsigned char *buf, int len )
{
    int i;

    if( len < 0 )
        return;

    printf( "%s(%04d): dumping '%s' (%d bytes)\n",
            file, line, text, len );

    for( i = 0; i < len; i++ )
    {
        if( i >= 4096 )
            break;

        if( i % 16 == 0 )
        {
            if( i > 0 ) printf( "\n" );
            printf( "%s(%04d): %04x: ", file, line, i );
        }

        printf( " %02x", (unsigned int) buf[i] );
    }

    if( len > 0 )
        printf( "\n" );
}

void debug_print_mpi( char *file, int line, char *text, mpi *X )
{
    int i, j, k, n, l;

    if( X == NULL )
        return;

    l = sizeof( t_int );

    for( n = X->n - 1; n >= 0; n-- )
        if( X->p[n] != 0 )
            break;

    printf( "%s(%04d): value of bignum '%s' (%d bytes) is:\n",
            file, line, text, l * ( n + 1 ) );

    for( i = n, j = 0; i >= 0; i--, j++ )
    {
        if( j % ( 16 / sizeof( t_int ) ) == 0 )
        {
            if( j > 0 ) printf( "\n" );
            printf( "%s(%04d): %04x: ", file, line, j * l );
        }

        for( k = l - 1; k >= 0; k-- )
            printf( " %02x", (unsigned int)
                ( X->p[i] >> (k << 3) ) & 0xFF );
    }

    printf( "\n" );
}

void debug_print_crt( char *file, int line, char *text, x509_cert *crt )
{
    int i = 0;
    char prefix[64], *p;

    if( crt == NULL )
        return;

    sprintf( prefix, "%s(%04d): ", file, line );

    while( crt != NULL && crt->next != NULL )
    {
        if( ( p = x509parse_cert_info( prefix, crt ) ) != NULL )
        {
            printf( "%s(%04d): %s #%d:\n%s", file, line, text, ++i, p );
            free( p );
        }

        debug_print_mpi( file, line, "crt->rsa.N", &crt->rsa.N );
        debug_print_mpi( file, line, "crt->rsa.E", &crt->rsa.E );

        crt = crt->next;
    }
}

#endif
