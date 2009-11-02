/**
 * \file net.h
 */
#ifndef _NET_H
#define _NET_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_NET_UNKNOWN_HOST            0x1000
#define ERR_NET_CONNECT_FAILED          0x2000
#define ERR_NET_SOCKET_FAILED           0x3000
#define ERR_NET_BIND_FAILED             0x4000
#define ERR_NET_LISTEN_FAILED           0x5000
#define ERR_NET_ACCEPT_FAILED           0x6000
#define ERR_NET_READ_FAILED             0x7000
#define ERR_NET_CONN_RESET              0x8000
#define ERR_NET_WRITE_FAILED            0x9000

/**
 * \brief          Initiate a TCP connection with hostname:port
 */
int net_connect( int *server_fd, char *hostname, uint port );

/**
 * \brief          Create a listening socket on ip:port. Set bind_ip
 *                 to NULL to listen on all network interfaces.
 */
int net_bind( int *server_fd, char *bind_ip, uint port );

/**
 * \brief          Accept a connection from a remote client
 */
int net_accept( int server_fd, int *client_fd, ulong *client_ip );

/**
 * \brief          Loop until "len" characters have been read
 */
int net_read_all( int read_fd, uchar *buf, uint len );

/**
 * \brief          Loop until "len" characters have been written
 */
int net_write_all( int write_fd, uchar *buf, uint len );

/**
 * \brief          Gracefully shutdown the connection
 */
void net_close( int sock_fd );

#ifdef __cplusplus
}
#endif

#endif /* net.h */
