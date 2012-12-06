/***************************************************************************
 * http.h                                                                  *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, version detection, and the Nmap Scripting Engine.            *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap, as well as other software we distribute under this       *
 * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
 * but is meant to clarify our interpretation of derived works with some   *
 * common examples.  Our interpretation applies only to Nmap--we don't     *
 * speak for other people's GPL works.                                     *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef _HTTP_H
#define _HTTP_H

#include "ncat_config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

/* This is an abstraction over a socket (really a struct fdinfo) that provides
   rudimentary buffering. It is useful for the line-oriented parts of HTTP. */
struct socket_buffer {
    struct fdinfo fdn;
    char buffer[BUFSIZ];
    char *p;
    char *end;
};

void socket_buffer_init(struct socket_buffer *buf, int sd);

int socket_buffer_read(struct socket_buffer *buf, char *out, size_t size);

char *socket_buffer_readline(struct socket_buffer *buf, size_t *n, size_t maxlen);

int socket_buffer_readcount(struct socket_buffer *buf, char *out, size_t size);

char *socket_buffer_remainder(struct socket_buffer *buf, size_t *len);

/* A broken-down URI as defined in RFC 3986, except that the query and fragment
   parts are included in the path. */
struct uri {
    char *scheme;
    char *host;
    int port;
    char *path;
};

void uri_init(struct uri *uri);

void uri_free(struct uri *uri);

struct uri *uri_parse(struct uri *uri, const char *uri_s);

struct uri *uri_parse_authority(struct uri *uri, const char *authority);

enum http_version {
    HTTP_09,
    HTTP_10,
    HTTP_11,
    HTTP_UNKNOWN,
};

struct http_header {
    char *name;
    char *value;
    struct http_header *next;
};

struct http_request {
    char *method;
    struct uri uri;
    enum http_version version;
    struct http_header *header;
    unsigned long content_length;
    unsigned long bytes_transferred;
};

struct http_response {
    enum http_version version;
    int code;
    char *phrase;
    struct http_header *header;
    unsigned long content_length;
    unsigned long bytes_transferred;
};

void http_header_free(struct http_header *header);
char *http_header_get(const struct http_header *header, const char *name);
const struct http_header *http_header_next(const struct http_header *header, const struct http_header *p, const char *name);
char *http_header_get_first(const struct http_header *header, const char *name);
struct http_header *http_header_set(struct http_header *header, const char *name, const char *value);
struct http_header *http_header_remove(struct http_header *header, const char *name);
int http_header_remove_hop_by_hop(struct http_header **header);
char *http_header_to_string(const struct http_header *header, size_t *n);

void http_request_init(struct http_request *request);
void http_request_free(struct http_request *request);
char *http_request_to_string(const struct http_request *request, size_t *n);

void http_response_init(struct http_response *response);
void http_response_free(struct http_response *response);
char *http_response_to_string(const struct http_response *response, size_t *n);

int http_read_header(struct socket_buffer *buf, char **result);
int http_parse_header(struct http_header **result, const char *header);
int http_request_parse_header(struct http_request *request, const char *header);
int http_response_parse_header(struct http_response *response, const char *header);

int http_read_request_line(struct socket_buffer *buf, char **line);
int http_parse_request_line(const char *line, struct http_request *request);

int http_read_status_line(struct socket_buffer *buf, char **line);
int http_parse_status_line(const char *line, struct http_response *response);
int http_parse_status_line_code(const char *line);

enum http_auth_scheme { AUTH_UNKNOWN, AUTH_BASIC, AUTH_DIGEST };
enum http_digest_algorithm { ALGORITHM_MD5, ALGORITHM_UNKNOWN };
enum http_digest_qop { QOP_NONE = 0, QOP_AUTH = 1 << 0, QOP_AUTH_INT = 1 << 1 };

struct http_challenge {
    enum http_auth_scheme scheme;
    char *realm;
    struct {
        char *nonce;
        char *opaque;
        enum http_digest_algorithm algorithm;
        /* A bit mask of supported qop values ("auth", "auth-int", etc.). */
        unsigned char qop;
    } digest;
};

struct http_credentials {
    enum http_auth_scheme scheme;
    union {
        char *basic;
        struct {
            char *username;
            char *realm;
            char *nonce;
            char *uri;
            char *response;
            enum http_digest_algorithm algorithm;
            enum http_digest_qop qop;
            char *nc;
            char *cnonce;
        } digest;
    } u;
};

void http_challenge_init(struct http_challenge *challenge);
void http_challenge_free(struct http_challenge *challenge);
struct http_challenge *http_header_get_proxy_challenge(const struct http_header *header, struct http_challenge *challenge);

void http_credentials_init_basic(struct http_credentials *credentials);
void http_credentials_init_digest(struct http_credentials *credentials);
void http_credentials_free(struct http_credentials *credentials);
struct http_credentials *http_header_get_proxy_credentials(const struct http_header *header, struct http_credentials *credentials);

#if HAVE_HTTP_DIGEST
/* Initialize the server secret used in generating nonces. */
int http_digest_init_secret(void);
int http_digest_nonce_time(const char *nonce, struct timeval *tv);
/* Return a Proxy-Authenticate header. */
char *http_digest_proxy_authenticate(const char *realm, int stale);
/* Return a Proxy-Authorization header answering the given challenge. */
char *http_digest_proxy_authorization(const struct http_challenge *challenge,
    const char *username, const char *password,
    const char *method, const char *uri);
int http_digest_check_credentials(const char *username, const char *realm,
    const char *password, const char *method,
    const struct http_credentials *credentials);
#endif

#endif
