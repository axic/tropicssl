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

int myrand( void *rng_state )
{
    rng_state = NULL;
    return( rand() );
}

int main( void )
{
    int keysize;
    unsigned long i, j, tsc;
    unsigned char buf[BUFSIZE];
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
        md4_csum( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md4_csum( buf, BUFSIZE, tmp );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * MD5 timing
     */ 
    printf( "  MD5       :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        md5_csum( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md5_csum( buf, BUFSIZE, tmp );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * SHA-1 timing
     */ 
    printf( "  SHA-1     :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha1_csum( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha1_csum( buf, BUFSIZE, tmp );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * SHA-256 timing
     */ 
    printf( "  SHA-256   :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha2_csum( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha2_csum( buf, BUFSIZE, tmp );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
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

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * Triple-DES timing
     */ 
    printf( "  3DES      :  " );
    fflush( stdout );

    des3_set_3keys( &des3, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des3_cbc_encrypt( &des3, tmp, buf, buf, BUFSIZE );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des3_cbc_encrypt( &des3, tmp, buf, buf, BUFSIZE );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * DES timing
     */ 
    printf( "  DES       :  " );
    fflush( stdout );

    des_set_key( &des, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des_cbc_encrypt( &des, tmp, buf, buf, BUFSIZE );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des_cbc_encrypt( &des, tmp, buf, buf, BUFSIZE );

    printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    /*
     * AES timings
     */ 
    for( keysize = 128; keysize <= 256; keysize += 64 )
    {
        printf( "  AES-%d   :  ", keysize );
        fflush( stdout );

        aes_set_key( &aes, tmp, keysize );

        set_alarm( 1 );

        for( i = 1; ! alarmed; i++ )
            aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

        tsc = hardclock();
        for( j = 0; j < 1024; j++ )
            aes_cbc_encrypt( &aes, tmp, buf, buf, BUFSIZE );

        printf( "%9ld Kb/s,  %9ld cycles/byte\n", i * BUFSIZE / 1024,
                        ( hardclock() - tsc ) / ( j * BUFSIZE ) );
    }

    /*
     * RSA-1024 timing
     */ 
    memset( &rsa, 0, sizeof( rsa ) );

    rsa.len = 128;

    mpi_read( &rsa.N , "9292758453063D803DD603D5E777D788" \
                       "8ED1D5BF35786190FA2F23EBC0848AEA" \
                       "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                       "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                       "93A89813FBF3C4F8066D2D800F7C38A8" \
                       "1AE31942917403FF4946B0A83D3D3E05" \
                       "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                       "5E94BB77B07507233A0BC7BAC8F90F79", 16 );

    mpi_read( &rsa.E , "10001", 16 );
    mpi_read( &rsa.D , "24BF6185468786FDD303083D25E64EFC" \
                       "66CA472BC44D253102F8B4A9D3BFA750" \
                       "91386C0077937FE33FA3252D28855837" \
                       "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                       "DF79C5CE07EE72C7F123142198164234" \
                       "CABB724CF78B8173B9F880FC86322407" \
                       "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                       "071513A1E85B5DFA031F21ECAE91A34D", 16 );

    mpi_read( &rsa.P , "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                       "2C01CAD19EA484A87EA4377637E75500" \
                       "FCB2005C5C7DD6EC4AC023CDA285D796" \
                       "C3D9E75E1EFC42488BB4F1D13AC30A57", 16 );
    mpi_read( &rsa.Q , "C000DF51A7C77AE8D7C7370C1FF55B69" \
                       "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                       "910E4168387E3C30AA1E00C339A79508" \
                       "8452DD96A9A5EA5D9DCA68DA636032AF", 16 );

    mpi_read( &rsa.DP, "C1ACF567564274FB07A0BBAD5D26E298" \
                       "3C94D22288ACD763FD8E5600ED4A702D" \
                       "F84198A5F06C2E72236AE490C93F07F8" \
                       "3CC559CD27BC2D1CA488811730BB5725", 16 );
    mpi_read( &rsa.DQ, "4959CBF6F8FEF750AEE6977C155579C7" \
                       "D8AAEA56749EA28623272E4F7D0592AF" \
                       "7C1F1313CAC9471B5C523BFE592F517B" \
                       "407A1BD76C164B93DA2D32A383E58357", 16 );
    mpi_read( &rsa.QP, "9AE7FBC99546432DF71896FC239EADAE" \
                       "F38D18D2B2F0E2DD275AA977E2BF4411" \
                       "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                       "A74206CEC169D74BF5A8C50D6F48EA08", 16 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, 128, buf, 128 );
    }

    printf( "%9ld  public/s\n", i / 3 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, 128, buf, 128 );
    }

    printf( "%9ld private/s\n\n", i / 3 );

    rsa_free( &rsa );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
