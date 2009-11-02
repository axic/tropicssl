/*
 *  Example RSA key generation program
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdio.h>

#include "xyssl/havege.h"
#include "xyssl/bignum.h"
#include "xyssl/rsa.h"

#define KEY_SIZE 1024
#define EXPONENT 65537

int main( void )
{
    int ret;
    rsa_context rsa;
    havege_state hs;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    havege_init( &hs );

    printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    if( ( ret = rsa_gen_key( &rsa, KEY_SIZE, EXPONENT,
                             havege_rand, &hs ) ) != 0 )
    {
        printf( " failed\n  ! rsa_gen_key returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n  . Exporting the public  key in rsa_pub.txt...." );
    fflush( stdout );

    if( ( fpub = fopen( "rsa_pub.txt", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        ret = 1;
        goto exit;
    }

    if( ( ret = rsa_write_public( &rsa, fpub ) ) != 0 )
    {
        printf( " failed\n  ! rsa_write_public returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n  . Exporting the private key in rsa_priv.txt..." );
    fflush( stdout );

    if( ( fpriv = fopen( "rsa_priv.txt", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_priv.txt for writing\n" );
        ret = 1;
        goto exit;
    }

    if( ( ret = rsa_write_private( &rsa, fpriv ) ) != 0 )
    {
        printf( " failed\n  ! rsa_write_private returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n\n" );

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    rsa_free( &rsa );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
