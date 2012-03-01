
/***************************************************************************
 * EchoClient.h --                                                         *
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
#ifndef __ECHOCLIENT_H__
#define __ECHOCLIENT_H__ 1

#include "nping.h"
#include "NpingTarget.h"
#include "NEPContext.h"
#include "ProbeMode.h"

#define ECHO_CONNECT_TIMEOUT (10*1000) /* 10 Seconds */
#define ECHO_READ_TIMEOUT    (10*1000)
#define ECHO_WRITE_TIMEOUT   (10*1000)

/* Max number of bytes that are supplied as data for the PAYLOAD_MAGIC specifier */
#define NEP_PAYLOADMAGIC_MAX_BYTES 8


class EchoClient  {

    private:

        /* Attributes */
        nsock_pool nsp;               /**< Nsock pool (shared with ProbeMode) */
        nsock_iod nsi;                /**< IOD for the side-channel tcp socket*/
        struct sockaddr_in srvaddr4;  /**< Server's IPv4 address */
        struct sockaddr_in6 srvaddr6; /**< Server's IPv6 address */
        int af;                       /**< Address family (AF_INET or AF_INET6)*/
        NEPContext ctx;
        ProbeMode probe;
        u8 lasthdr[MAX_NEP_PACKET_LENGTH];
        size_t readbytes;
        
        /* Methods */
        int nep_connect(NpingTarget *target, u16 port);
        int nep_handshake();
        int nep_send_packet_spec();
        int nep_recv_ready();
        int nep_recv_echo(u8 *packet, size_t packetlen);

        int parse_hs_server(u8 *pkt, size_t pktlen);
        int parse_hs_final(u8 *pkt, size_t pktlen);
        int parse_ready(u8 *pkt, size_t pktlen);
        int parse_echo(u8 *pkt, size_t pktlen);
        int parse_error(u8 *pkt, size_t pktlen);

        int generate_hs_client(EchoHeader *h);
        int generate_packet_spec(EchoHeader *h);

    public:

        EchoClient();
        ~EchoClient();
        void reset();
        int start(NpingTarget *target, u16 port);
        int cleanup();
        int nep_echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg);
        int nep_recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg);

}; /* End of class EchoClient */


/* Handler wrappers */
void echoed_packet_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_std_header_handler(nsock_pool nsp, nsock_event nse, void *arg);
void connect_done_handler(nsock_pool nsp, nsock_event nse, void *arg);
void write_done_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_hs_server_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_hs_final_handler(nsock_pool nsp, nsock_event nse, void *arg);
void recv_ready_handler(nsock_pool nsp, nsock_event nse, void *arg);

#endif /* __ECHOCLIENT_H__ */
