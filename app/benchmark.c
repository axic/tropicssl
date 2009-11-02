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

#define BUFSIZE 1024

int alarmed;

#ifdef WIN32
#include <windows.h>

DWORD WINAPI TimerProc( LPVOID uElapse )
{
    Sleep( (DWORD) uElapse );
    alarmed = 1;
    return( TRUE );
}

void set_alarm( int timeout )
{
    DWORD ThreadId;

    alarmed = 0;
    CloseHandle( CreateThread( NULL, 0, TimerProc,
        (LPVOID) ( timeout * 1000 ), 0, &ThreadId ) );
}
#else
#include <unistd.h>
#include <signal.h>

void sighandler( int signum )
{
    alarmed = 1;
    signal( signum, sighandler );
}

void set_alarm( int timeout )
{
    alarmed = 0;
    signal( SIGALRM, sighandler );
    alarm( timeout );
}
#endif

ulong myrand( void *rng_state )
{
    rng_state = NULL;
    return( (ulong) rand() );
}

int main( void )
{
    ulong i, tsc;
    uchar buf[BUFSIZE];
    uchar tmp[32];
    md2_context md2;
    md4_context md4;
    md5_context md5;
    sha1_context sha1;
    sha2_context sha2;
    arc4_context arc4;
    des3_context des;
    aes_context aes;
    rsa_context rsa;

    memset( buf, 0xAA, sizeof( buf ) );

    printf( "\n" );

    /*
     * MD2 timing
     */ 
    printf( "  MD2       :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    for( i = 1; ! alarmed; i++ )
    {
        md2_starts( &md2 );
        md2_update( &md2, buf, BUFSIZE );
        md2_finish( &md2, tmp );
    }

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * MD4 timing
     */ 
    printf( "  MD4       :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    for( i = 1; ! alarmed; i++ )
    {
        md4_starts( &md4 );
        md4_update( &md4, buf, BUFSIZE );
        md4_finish( &md4, tmp );
    }

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * MD5 timing
     */ 
    printf( "  MD5       :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    for( i = 1; ! alarmed; i++ )
    {
        md5_starts( &md5 );
        md5_update( &md5, buf, BUFSIZE );
        md5_finish( &md5, tmp );
    }

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * SHA-1 timing
     */ 
    printf( "  SHA-1     :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    for( i = 1; ! alarmed; i++ )
    {
        sha1_starts( &sha1 );
        sha1_update( &sha1, buf, BUFSIZE );
        sha1_finish( &sha1, tmp );
    }

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * SHA-256 timing
     */ 
    printf( "  SHA-256   :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    for( i = 1; ! alarmed; i++ )
    {
        sha2_starts( &sha2 );
        sha2_update( &sha2, buf, BUFSIZE );
        sha2_finish( &sha2, tmp );
    }

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * ARC4 timing
     */ 
    printf( "  ARC4      :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    arc4_setup( &arc4, tmp, 32 );
    for( i = 1; ! alarmed; i++ )
        arc4_crypt( &arc4, buf, BUFSIZE );

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * Triple-DES timing
     */ 
    printf( "  DES-EDE3  :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    des3_set_3keys( &des, tmp );
    for( i = 1; ! alarmed; i++ )
        des3_cbc_encrypt( &des, tmp, buf, buf, BUFSIZE );

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * AES-128 timing
     */ 
    printf( "  AES-128   :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 128 );
    for( i = 1; ! alarmed; i++ )
        aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * AES-192 timing
     */ 
    printf( "  AES-192   :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 192 );
    for( i = 1; ! alarmed; i++ )
        aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * AES-256 timing
     */ 
    printf( "  AES-256   :  " );
    fflush( stdout );

    set_alarm( 1 );
    tsc = hardclock();

    aes_set_key( &aes, tmp, 256 );
    for( i = 1; ! alarmed; i++ )
        aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

    printf( "%9ld  bytes/s,  %9ld cycles/byte\n", i * BUFSIZE,
            ( hardclock() - tsc ) / ( i * BUFSIZE ) );

    /*
     * RSA-1024 timing
     */ 
    printf( "  RSA-1024  :  " );
    fflush( stdout );

    rsa_gen_key( &rsa, 1024, 65537, myrand, NULL );
    set_alarm( 4 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, 128, buf, 128 );
    }

    printf( "%9ld  public/s\n", i / 4 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 4 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, 128, buf, 128 );
    }

    printf( "%9ld private/s\n", i / 4 );

    rsa_free( &rsa );

    /*
     * RSA-2048 timing
     */ 
    printf( "  RSA-2048  :  " );
    fflush( stdout );

    rsa_gen_key( &rsa, 2048, 65537, myrand, NULL );
    set_alarm( 4 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, 256, buf, 256 );
    }

    printf( "%9ld  public/s\n", i / 4 );

    printf( "  RSA-2048  :  " );
    fflush( stdout );

    set_alarm( 4 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, 256, buf, 256 );
    }

    printf( "%9ld private/s\n\n", i / 4 );

    rsa_free( &rsa );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
