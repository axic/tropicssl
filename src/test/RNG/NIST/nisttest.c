#include <stdlib.h>
#include <stdio.h>

#include "PackTest.c"

int main( int argc, char *argv[] )
{
    unsigned long n = 0;
    unsigned char *buf;
    FILE *f = fopen( argv[1], "rb" );

    if( argc < 2 )
    {
        printf( "usage: %s <32Mb rand file>\n", argv[0] );
        return( 1 );
    }

    if( f == NULL )
    {
        perror( "fopen" );
        return( 1 );
    }

    buf = malloc( 32 * 1048576 );
    while( fread( buf + n, 1024, 1, f ) == 1 )
        n += 1024;
    fclose( f );

    PackTestF( (int *) buf, 8192 * 1024, "resout" );
    PackTestL( (int *) buf, 8192 * 1024, "resout" );

    return( 0 );
}
