/***************************************************************************
 * sys_wrap.c -- Error-checked wrappers around common functions.           *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
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
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include <limits.h>

#include "sys_wrap.h"
#include "util.h"

void *Calloc(size_t nmemb, size_t size)
{
    void    *ret;

    /* older libcs don't check for int overflow */
    smul(nmemb, size);

    ret = calloc(nmemb, size);
    if (ret == NULL)
        die("calloc");

    return ret;
}

int Close(int fd)
{
    if (close(fd) < 0)
        die("close");

    return 0;
}

int Connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
    if (connect(sockfd, serv_addr, addrlen) < 0)
        die("connect");

    return 0;
}

int Dup2(int oldfd, int newfd)
{
    int ret;

    ret = dup2(oldfd, newfd);
    if (ret < 0)
        die("dup2");

    return ret;
}

int Listen(int s, int backlog)
{
    if (listen(s, backlog) < 0)
        die("listen");

    return 0;
}

int Open(const char *pathname, int flags, mode_t mode)
{
    int ret;

    ret = open(pathname, flags, mode);
    if (ret < 0)
        die("open");

    return ret;
}

ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t ret;

    ret = read(fd, buf, count);
    if (ret < 0)
        die("read");

    return ret;
}

ssize_t Recv(int s, void *buf, size_t len, int flags)
{
    ssize_t ret;

    ret = recv(s, (char*)buf, len, flags);
    if (ret < 0)
        die("recv");

    return ret;
}

ssize_t Recvfrom(int s, void *buf, size_t len, int flags,
                    struct sockaddr *from, socklen_t *fromlen)
{
    ssize_t ret;

    ret = recvfrom(s, (char*)buf, len, flags, from, fromlen);
    if (ret < 0)
        die("recvfrom");

    return ret;
}

int Setsockopt(int s, int level, int optname, const void *optval,
                    socklen_t optlen)
{
    int ret;

    ret = setsockopt(s, level, optname, (const char*)optval, optlen);
    if (ret < 0)
        die("setsockopt");

    return ret;
}

sighandler_t Signal(int signum, sighandler_t handler)
{
    sighandler_t    ret;

    ret = signal(signum, handler);
    if (ret == SIG_ERR)
        die("signal");

    return ret;
}


int Socket(int domain, int type, int protocol)
{
    int ret;

    ret = socket(domain, type, protocol);
    if (ret < 0)
        die("socket");

    return ret;
}

char *Strdup(const char *s)
{
    char    *ret;

    ret = strdup(s);
    if (ret == NULL)
        die("strdup");

    return ret;
}

ssize_t Write(int fd, const void *buf, size_t count)
{
    ssize_t ret = write(fd, buf, count);

    if (ret < 0)         /* we don't bail if < count bytes written */
        die("write");

    return ret;
}
