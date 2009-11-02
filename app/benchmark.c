/*
 *  Benchmark demonstration program
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "arc4.h"
#include "des.h"
#include "aes.h"
#include "rsa.h"
#include "timing.h"

#define NB_ITER 2048
#define BUFSIZE 1024
#define TOTAL (NB_ITER*BUFSIZE)
#define NB_ITER2 128

ulong myrand( void *rng_state )
{
    rng_state = NULL;
    return( (ulong) rand() );
}

int main( void )
{
    int i;
    struct hr_time ht;
    uchar buf[BUFSIZE];
    uchar tmp[32];
    ulong tsc, u, v;

    md2_context md2;
    md4_context md4;
    md5_context md5;
    sha1_context sha1;
    sha2_context sha2;
    arc4_context arc4;
    des3_context des;
    aes_context aes;
    rsa_context rsa;

    printf( "\n" );

    /*
     * MD2 timing
     */ 
    tsc = hardclock();
    set_timer( &ht, 1 );

    md2_starts( &md2 );
    for( i = 0; i < NB_ITER; i++ )
        md2_update( &md2, buf, BUFSIZE );
    md2_finish( &md2, tmp );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  MD2       :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * MD4 timing
     */ 
    tsc = hardclock();
    set_timer( &ht, 1 );

    md4_starts( &md4 );
    for( i = 0; i < NB_ITER; i++ )
        md4_update( &md4, buf, BUFSIZE );
    md4_finish( &md4, tmp );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  MD4       :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * MD5 timing
     */ 
    tsc = hardclock();
    set_timer( &ht, 1 );

    md5_starts( &md5 );
    for( i = 0; i < NB_ITER; i++ )
        md5_update( &md5, buf, BUFSIZE );
    md5_finish( &md5, tmp );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  MD5       :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * SHA-1 timing
     */ 
    tsc = hardclock();
    set_timer( &ht, 1 );

    sha1_starts( &sha1 );
    for( i = 0; i < NB_ITER; i++ )
        sha1_update( &sha1, buf, BUFSIZE );
    sha1_finish( &sha1, tmp );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  SHA-1     :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * SHA-256 timing
     */ 
    tsc = hardclock();
    set_timer( &ht, 1 );

    sha2_starts( &sha2 );
    for( i = 0; i < NB_ITER; i++ )
        sha2_update( &sha2, buf, BUFSIZE );
    sha2_finish( &sha2, tmp );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  SHA-256   :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * ARC4 timing
     */ 
    set_timer( &ht, 1 );
    tsc = hardclock();

    arc4_setup( &arc4, tmp, 32 );
    for( i = 0; i < NB_ITER; i++ )
        arc4_crypt( &arc4, buf, BUFSIZE );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  ARC4      :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * Triple-DES timing
     */ 
    set_timer( &ht, 1 );
    tsc = hardclock();

    des3_set_3keys( &des, tmp );
    for( i = 0; i < NB_ITER; i++ )
        des3_cbc_encrypt ( &des, tmp, buf, buf, BUFSIZE );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  DES-EDE3  :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * AES-128 timing
     */ 
    set_timer( &ht, 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 128 );
    for( i = 0; i < NB_ITER; i++ )
        aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  AES-128   :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * AES-192 timing
     */ 
    set_timer( &ht, 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 192 );
    for( i = 0; i < NB_ITER; i++ )
        aes_cbc_encrypt ( &aes, tmp, buf, buf, BUFSIZE );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  AES-192   :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * AES-256 timing
     */ 
    set_timer( &ht, 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 256 );
    for( i = 0; i < NB_ITER; i++ )
        aes_cbc_encrypt ( &aes, tmp, buf, buf, BUFSIZE );

    v = (ulong)(( hardclock() - tsc ) / ( NB_ITER * BUFSIZE ));
    u = (ulong)( NB_ITER * BUFSIZE / ( set_timer( &ht, 0 ) ) );
    printf( "  AES-256   :  %9ld bytes/s,  %9ld cycles/byte\n", u, v );

    /*
     * RSA-1024 timing
     */ 
    rsa_gen_key( &rsa, 1024, 257, myrand, NULL );

    set_timer( &ht, 1 );

    for( i = 0; i < NB_ITER2; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, 128, buf, 128 );
    }

    u = (ulong)( NB_ITER2 / ( set_timer( &ht, 0 ) ) );
    printf( "  RSA-1024  :  %5ld verify op/s\n", u );

    set_timer( &ht, 1 );

    for( i = 0; i < NB_ITER2; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, 128, buf, 128 );
    }

    u = (ulong)( NB_ITER2 / ( set_timer( &ht, 0 ) ) );
    printf( "  RSA-1024  :  %5ld sign   op/s\n", u );

    /*
     * RSA-1536 timing
     */ 
    rsa_gen_key( &rsa, 1536, 41, myrand, NULL );

    set_timer( &ht, 1 );

    for( i = 0; i < NB_ITER2; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, 192, buf, 192 );
    }

    u = (ulong)( NB_ITER2 / ( set_timer( &ht, 0 ) ) );
    printf( "  RSA-1536  :  %5ld verify op/s\n", u );

    set_timer( &ht, 1 );

    for( i = 0; i < NB_ITER2; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, 192, buf, 192 );
    }

    u = (ulong)( NB_ITER2 / ( set_timer( &ht, 0 ) ) );
    printf( "  RSA-1536  :  %5ld sign   op/s\n", u );

    printf( "\n" );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
