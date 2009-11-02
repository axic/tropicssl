/**
 * \file ssl_conf.h
 *
 *      Defines the set of features _not_ available,
 *       this is mostly useful for embedded systems.
 *
 *      Both MD5 and SHA-1 are required for SSL and
 *       therefore cannot be disabled here.
 *
 *  When compiling for ARMv3 / ARMv4T with gcc 3.4.6 -Os:
 *
 *  NO_GENPRIME  saves    2196 bytes
 *  NO_DHM       saves    2220 bytes
 *  NO_MD2       saves    2056 bytes
 *  NO_MD4       saves    3948 bytes
 *  NO_ARC4      saves     840 bytes
 *  NO_DES       saves   18016 bytes
 *  NO_AES       saves   19228 bytes
 *  NO_SSL_CLI   saves    2644 bytes
 *  NO_SSL_SRV   saves    3348 bytes
 */
#ifndef _SSL_CONF_H
#define _SSL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * For a minimalist SSL/TLS client:
 * (compiled size reduced by ~50 Kb)
 *
#define NO_GENPRIME
#define NO_DHM
#define NO_MD2
#define NO_MD4
#define NO_DES
#define NO_AES
#define NO_SSL_SRV
 */

/*
 * Don't include prime-number generation
 *
#define NO_GENPRIME
 */

/*
 * Don't include the DHM key exchange
 *
#define NO_DHM
 */

/*
 * Don't include the MD2 hash function
 *
#define NO_MD2
 */

/*
 * Don't include the MD4 hash function
 *
#define NO_MD4
 */

/*
 * Don't include the ARC4 cipher
 *
#define NO_ARC4
 */

/*
 * Don't include the DES/3DES ciphers
 *
#define NO_DES
 */

/*
 * Don't include the AES cipher
 *
#define NO_AES
 */

/*
 * Don't include SSL client-side code
 *
#define NO_SSL_CLI
 */

/*
 * Don't include SSL server-side code
 *
#define NO_SSL_SRV
 */

#ifdef __cplusplus
}
#endif

#endif /* ssl_conf.h */
