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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "xyssl/md4.h"
#include "xyssl/md5.h"
#include "xyssl/sha1.h"
#include "xyssl/sha2.h"
#include "xyssl/arc4.h"
#include "xyssl/des.h"
#include "xyssl/aes.h"
#include "xyssl/rsa.h"
#include "xyssl/timing.h"

#define BUFSIZE 1024

static int myrand( void *rng_state )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    return( rand() );
}

unsigned char buf[BUFSIZE];

int main( void )
{
    int keysize;
    unsigned long i, j, tsc;
    unsigned char tmp[32];
    arc4_context arc4;
    des3_context des3;
    des_context des;
    aes_context aes;
    rsa_context rsa;

    memset( buf, 0xAA, sizeof( buf ) );

    printf( "\n" );

    /*
     * MD4 timing
     */ 
    printf( "  MD4       :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        md4( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md4( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * MD5 timing
     */ 
    printf( "  MD5       :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        md5( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md5( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * SHA-1 timing
     */ 
    printf( "  SHA-1     :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha1( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha1( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * SHA-256 timing
     */ 
    printf( "  SHA-256   :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha2( buf, BUFSIZE, tmp, 0 );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha2( buf, BUFSIZE, tmp, 0 );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * ARC4 timing
     */ 
    printf( "  ARC4      :  " );
    fflush( stdout );

    arc4_setup( &arc4, tmp, 32 );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        arc4_crypt( &arc4, buf, BUFSIZE );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        arc4_crypt( &arc4, buf, BUFSIZE );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * Triple-DES timing
     */ 
    printf( "  3DES      :  " );
    fflush( stdout );

    des3_set3key_enc( &des3, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des3_crypt_cbc( &des3, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des3_crypt_cbc( &des3, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * DES timing
     */ 
    printf( "  DES       :  " );
    fflush( stdout );

    des_setkey_enc( &des, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des_crypt_cbc( &des, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des_crypt_cbc( &des, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * AES timings
     */ 
    for( keysize = 128; keysize <= 256; keysize += 64 )
    {
        printf( "  AES-%d   :  ", keysize );
        fflush( stdout );

        memset( buf, 0, sizeof( buf ) );
        memset( tmp, 0, sizeof( tmp ) );
        aes_setkey_enc( &aes, tmp, keysize );

        set_alarm( 1 );

        for( i = 1; ! alarmed; i++ )
            aes_crypt_cbc( &aes, AES_ENCRYPT, BUFSIZE, tmp, buf, buf );

        tsc = hardclock();
        for( j = 0; j < 4096; j++ )
            aes_crypt_cbc( &aes, AES_ENCRYPT, BUFSIZE, tmp, buf, buf );

        printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                        ( hardclock() - tsc ) / ( j * BUFSIZE ) );
    }

    /*
     * RSA-1024 timing
     */ 
    rsa_init( &rsa, RSA_PKCS_V15, 0, myrand, NULL );
    rsa_gen_key( &rsa, 1024, 65537 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, buf );
    }

    printf( "%9lu  public/s\n", i / 3 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, buf );
    }

    printf( "%9lu private/s\n\n", i / 3 );

    rsa_free( &rsa );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
