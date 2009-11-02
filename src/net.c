/*
 *  TCP networking functions
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

#ifndef WIN32

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#define recv(a,b,c,d)   read(a,b,c)
#define send(a,b,c,d)   write(a,b,c)
#define closesocket(fd) close(fd)

#else

#include <winsock2.h>
#include <windows.h>

#pragma comment( lib, "ws2_32.lib" )

static int wsa_init_done = 0;

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "net.h"

/*
 * Initiate a TCP connection with hostname:port
 */
int net_connect( int *server_fd, char *hostname, uint port )
{
    struct sockaddr_in server_addr;
    struct hostent *server_host;

#ifdef WIN32
    WSADATA wsaData;

    if( wsa_init_done == 0 )
    {
        if( WSAStartup( MAKEWORD(2,0), &wsaData ) == SOCKET_ERROR )
            return( ERR_NET_SOCKET_FAILED );

        wsa_init_done = 1;
    }
#endif

    if( ( server_host = gethostbyname( hostname ) ) == NULL )
        return( ERR_NET_UNKNOWN_HOST );

    if( ( *server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP ) ) < 0 )
        return( ERR_NET_SOCKET_FAILED );

    memcpy( (void *) &server_addr.sin_addr,
            (void *) server_host->h_addr,
                     server_host->h_length );

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons( (unsigned short) port );

    if( connect( *server_fd, (struct sockaddr *) &server_addr,
                 sizeof( server_addr ) ) < 0 )
    {
        closesocket( *server_fd );
        return( ERR_NET_CONNECT_FAILED );
    }

    return( 0 );
}

/*
 * Create a listening socket on ip:port. Set bind_ip
 * to NULL to listen on all network interfaces.
 */
int net_bind( int *server_fd, char *bind_ip, uint port )
{
    struct sockaddr_in server_addr;

#ifdef WIN32
    WSADATA wsaData;

    if( wsa_init_done == 0 )
    {
        if( WSAStartup( MAKEWORD(2,0), &wsaData ) == SOCKET_ERROR )
            return( ERR_NET_SOCKET_FAILED );

        wsa_init_done = 1;
    }
#endif

    *server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    if( *server_fd < 0 )
        return( ERR_NET_SOCKET_FAILED );

    server_addr.sin_addr.s_addr = ( bind_ip != NULL ) ?
                         inet_addr( bind_ip ) : INADDR_ANY;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons( (unsigned short) port );

    if( bind( *server_fd, (struct sockaddr *) &server_addr,
              sizeof( server_addr ) ) < 0 )
    {
        closesocket( *server_fd );
        return( ERR_NET_BIND_FAILED );
    }

    if( listen( *server_fd, 10 ) != 0 )
    {
        closesocket( *server_fd );
        return( ERR_NET_LISTEN_FAILED );
    }

    return( 0 );
}

/*
 * Accept a connection from a remote client
 */
int net_accept( int server_fd, int *client_fd, ulong *client_ip )
{
    struct sockaddr_in client_addr;
    uint n = sizeof( client_addr );

    *client_fd = accept( server_fd, (struct sockaddr *)
                         &client_addr, &n );

    if( *client_fd < 0 )
        return( ERR_NET_ACCEPT_FAILED );

    if( client_ip != NULL )
        memcpy( client_ip, &client_addr.sin_addr.s_addr, 4 );

    return( 0 );
}

/*
 * Return 1 if data is available at the transport layer,
 * or 0 otherwise (in which case read() is blocking).
 */
int net_is_data_avail( int fd )
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO( &rfds );
    FD_SET( (unsigned int) fd, &rfds );

    tv.tv_sec  = 0;
    tv.tv_usec = 0;

    if( select( fd + 1, &rfds, NULL, NULL, &tv ) <= 0 )
        return( 1 );

    return( 0 );
}

/*
 * Loop until "len" characters have been read.
 */
int net_read_all( int read_fd, uchar *buf, uint len )
{
    int ret;
    uint n = 0;

    while( n < len )
    {
        if( ( ret = recv( read_fd, buf + n, len - n, 0 ) ) <= 0 )
        {
#ifndef WIN32
            if( errno == EAGAIN || errno == EINTR )
            {
                usleep( 10000 );
                continue;
            }
#endif
            if( ret == 0 )
                return( ERR_NET_CONN_RESET );
            else
                return( ERR_NET_READ_FAILED );
        }

        n += ret;
    }

    return( 0 );
}

/*
 * Loop until "len" characters have been written.
 */
int net_write_all( int write_fd, uchar *buf, uint len )
{
    int ret;
    uint n = 0;

    while( n < len )
    {
        if( ( ret = send( write_fd, buf + n, len - n, 0 ) ) < 0 )
        {
#ifndef WIN32
            if( errno == EAGAIN || errno == EINTR )
            {
                usleep( 10000 );
                continue;
            }

            if( errno == EPIPE )
                return( ERR_NET_CONN_RESET );
#else
            if( WSAGetLastError() == WSAECONNRESET )
                return( ERR_NET_CONN_RESET );
#endif
            return( ERR_NET_WRITE_FAILED );
        }

        n += ret;
    }

    return( 0 );
}

/*
 * Gracefully shutdown the connection
 */
void net_close( int sock_fd )
{
    shutdown( sock_fd, 2 );
    closesocket( sock_fd );
}
