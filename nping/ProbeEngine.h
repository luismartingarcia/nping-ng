
/***************************************************************************
 * ProbeEngine.h -- Probe Mode is nping's default working mode. Basically,   *
 * it involves sending the packets that the user requested at regular      *
 * intervals and capturing responses from the wire.                        *
 *                                                                         *
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
#ifndef __PROBE_ENGINE_H__
#define __PROBE_ENGINE_H__ 1



#include "nping.h"
#include "nsock.h"
#include <vector>
#include "TargetHost.h"
#include "utils_net.h"
#include "utils.h"
using namespace std;

/* DEFAULT_MAX__DESCRIPTORS. is a hardcoded value for the maximum number of
 * opened descriptors in the current system. Nping tries to determine that
 * limit at run time, but sometimes it can't and the limit defaults to
 * DEFAULT_MAX_DESCRIPTORS. */
#ifndef MACOSX
    #define DEFAULT_MAX_DESCRIPTORS 1024
#else
    #define DEFAULT_MAX_DESCRIPTORS 256
#endif

/* When requesting a large number of descriptors from the system (TCP-connect
 * mode and UDP unprivileged mode), this is the number of descriptors that need
 * to be reserved for things like stdin, stdout, echo mode sockets, data files,
 * etc. */
#define RESERVED_DESCRIPTORS 8

/* Default timeout for UDP socket nsock_read() operations */
#define DEFAULT_UDP_READ_TIMEOUT_MS  1000

/* Amount of time we keep capturing responses after the last packet is sent,
 * providing we have no measured RTT for any of the hosts. */
#define DEFAULT_TIME_WAIT_AFTER_LAST_PACKET 1000


class ProbeEngine  {

  public:
    struct timeval start_time;   /* Time at which the engine was started    */
    struct timeval ts_last_sent; /* Time at which the engine was started    */

  private:
    nsock_pool nsp;              /* Internal Nsock pool                     */
    bool nsock_init;             /* True if Nsock pool has been initialized */
    vector<nsock_iod> pcap_iods; /* List of Nsock Pcap descriptors.         */

    int rawsd4;                  /* Raw socket descriptor for IPv4          */
    int rawsd6;                  /* Raw socket descriptor for IPv6          */
    nsock_iod *fds;              /* IODs for multiple parallel connections  */
    int max_iods;                /* Number of IODS in "fds"                 */
    u32 packetno;                /* Packets sent from this handler.         */

  public:

    ProbeEngine();
    ~ProbeEngine();
    void reset();
    int init_nsock();
    int start(vector<TargetHost *> &Targets, vector<NetworkInterface *> &Interfaces);
    int cleanup();
    nsock_pool getNsockPool();

    static char *bpf_filter(vector<TargetHost *> &Targets, NetworkInterface *target_interface);
    int setup_sniffer(vector<NetworkInterface *> &ifacelist, vector<const char *>bpf_filters);
    int send_packet(TargetHost *tgt, PacketElement *pkt, struct timeval *now);
    int do_unprivileged(int proto, TargetHost *tgt, u16 tport, u16 sport, struct timeval *now);
    int do_tcp_connect(TargetHost *tgt, u16 tport, u16 sport, struct timeval *now);
    int do_udp_unpriv(TargetHost *tgt, u16 tport, u16 sport, struct timeval *now);
    int packet_capture_handler(nsock_pool nsp, nsock_event nse, void *arg);
    int tcpconnect_handler(nsock_pool nsp, nsock_event nse, void *arg);
    int udpunpriv_handler(nsock_pool nsp, nsock_event nse, void *arg);
    static int delayed_output_handler(nsock_pool nsp, nsock_event nse, void *mydata);
    static int print_rcvd_pkt(PacketElement *pkt, float timestamp);

}; /* End of class ProbeEngine */


/* Handlers and handler wrappers */
void interpacket_delay_wait_handler(nsock_pool nsp, nsock_event nse, void *arg);
void packet_capture_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);
void tcpconnect_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);
void udpunpriv_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);
void delayed_output_handler_wrapper(nsock_pool nsp, nsock_event nse, void *arg);

#endif /* __PROBE_ENGINE_H__ */

