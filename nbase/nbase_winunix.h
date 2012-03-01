/***************************************************************************
 * nbase_winunix.h -- Misc. compatability routines that generally try to   *
 * reproduce UNIX-centric concepts on Windows.                             *
 *                                                                         *
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

#ifndef NBASE_WINUNIX_H
#define NBASE_WINUNIX_H

#include "nbase_winconfig.h"

/* Define the earliest version of Windows we support.  These control
   what parts of the Windows API are available. The available constants
   are in <sdkddkver.h>.
   http://msdn.microsoft.com/en-us/library/aa383745.aspx
   http://blogs.msdn.com/oldnewthing/archive/2007/04/11/2079137.aspx */
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN2K
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN2KSP4

/* Winsock defines its own error codes that are analogous to but
   different from those in <errno.h>. The error macros have similar
   names, for example
     EINTR -> WSAEINTR
     ECONNREFUSED -> WSAECONNREFUSED
   But the values are different. The errno codes are small integers,
   while the Winsock codes start at 10000 or so.
   http://msdn.microsoft.com/en-us/library/ms737828

   Later in this file there is a block of code that defines the errno
   names to their Winsock equivalents, so that you can write code using
   the errno names only, and have it still work on Windows. However this
   causes some problems that are worked around in the following few
   lines. First, we prohibit the inclusion of <errno.h>, so that the
   only error codes visible are those we explicitly define in this file.
   This will cause a compilation error if someone uses a code we're not
   yet aware of instead of using an incompatible value at runtime.
   Second, because <errno.h> is not defined, the C++0x header
   <system_error> doesn't compile, so we pretend not to have C++0x to
   avoid it. */
#define _INC_ERRNO  /* suppress errno.h */
#define _ERRNO_H_ /* Also for errno.h suppresion */
#define _SYSTEM_ERROR_
#define _HAS_CPP0X 0

/* Suppress winsock.h */
#define _WINSOCKAPI_
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* IPv6 stuff */
#if HAVE_WSPIAPI_H
/* <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
   available on some platforms like MinGW. */
#include <wspiapi.h>
#endif
#include <time.h>
#include <iptypes.h>
#include <stdlib.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>
#include <limits.h>
#include <WINCRYPT.H>
#include <math.h>


#define SIOCGIFCONF     0x8912          /* get iface list */

#ifndef GLOBALS
#define GLOBALS 1

#endif

#define munmap(ptr, len) win32_munmap(ptr, len)

/* Windows error message names */
#define ECONNABORTED    WSAECONNABORTED
#define ECONNRESET      WSAECONNRESET
#define ECONNREFUSED    WSAECONNREFUSED
#undef  EAGAIN
#define EAGAIN		WSAEWOULDBLOCK
#define EWOULDBLOCK	WSAEWOULDBLOCK
#define EHOSTUNREACH	WSAEHOSTUNREACH
#define ENETDOWN	WSAENETDOWN
#define ENETUNREACH	WSAENETUNREACH
#define ENETRESET	WSAENETRESET
#define ETIMEDOUT	WSAETIMEDOUT
#define EHOSTDOWN	WSAEHOSTDOWN
#define EINPROGRESS	WSAEINPROGRESS
#undef  EINVAL
#define EINVAL          WSAEINVAL      /* Invalid argument */
#undef  EPERM
#define EPERM           WSAEACCES      /* Operation not permitted */
#undef  EACCES
#define EACCES          WSAEACCES     /* Operation not permitted */
#undef  EINTR
#define EINTR           WSAEINTR      /* Interrupted system call */
#define ENOBUFS         WSAENOBUFS     /* No buffer space available */
#define EMSGSIZE        WSAEMSGSIZE    /* Message too long */
#undef  ENOMEM
#define ENOMEM          WSAENOBUFS
#undef  ENOTSOCK
#define ENOTSOCK        WSAENOTSOCK
#undef  EIO
#define EIO             WSASYSCALLFAILURE

/*
This is not used by our network code, and causes problems in programs using
Nbase that legitimately use ENOENT for file operations.
#undef  ENOENT
#define ENOENT          WSAENOENT
*/

#define close(x) closesocket(x)

typedef unsigned short u_short_t;

int win_stdin_start_thread(void);
int win_stdin_ready(void);

#endif /* NBASE_WINUNIX_H */
