
/***************************************************************************
 * NpingTarget.h -- The NpingTarget class encapsulates much of the         *
 * information Nping has about a host. Things like next hop address or the *
 * network interface that should be used to send probes to the target, are *
 * stored in this class as they are determined.                            *
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

#ifndef __TARGETHOST_H__
#define __TARGETHOST_H__ 1

#include "nping.h"
#include "NetworkInterface.h"
#include "HeaderTemplates.h"
#include <vector>
using namespace std;

/* The internal attribute net_distance may be tested for one of the following to
 * determine if we've discovered how far the target is. */
#define DISTANCE_UNKONWN -1   /* We don't know how far the host is. */
#define DISTANCE_DIRECT   0   /* The host is directly connected.    */

class TargetHost{

  private:
    IPAddress *target_addr;   /* Target's IP address                                  */
    IPAddress *source_addr;   /* Source address for packets sent to the target        */
    IPAddress *nxthop_addr;   /* Address of the gateway 2be used to reach the target  */

    MACAddress *target_mac;  /* Target's MAC. Valid only if tgt is directly connected */
    MACAddress *source_mac;  /* Source MAC address for frames sent to target          */
    MACAddress *nxthop_mac;  /* Destination MAC address for frames sent to target     */

    IPv4HeaderTemplate *ip4; /* Header values for IPv4                                */
    IPv6HeaderTemplate *ip6; /* Header values for IPv6                                */
    TCPHeaderTemplate *tcp;  /* Header values for TCP                                 */
    ICMPv4HeaderTemplate *icmp4; /* Header values for ICMPv4                          */

    int net_distance;        /* If >=0, indicates how many hops away the target is    */
    NetworkInterface *iface; /* Info about the proper interface to reach target       */

    IPv4Header *getIPv4Header(const char *next_proto);
    IPv6Header *getIPv6Header(const char *next_proto);
    TCPHeader *getTCPHeader();

  public:
    TargetHost();
    ~TargetHost();

    /* Target Host IP Address */
    int setTargetAddress(IPAddress *addr);
    IPAddress *getTargetAddress();

    /* Source IP Address */
    int setSourceAddress(IPAddress *addr);
    IPAddress *getSourceAddress();

    /* Next Hop IP Address */
    int setNextHopAddress(IPAddress *addr);
    IPAddress *getNextHopAddress();

    /* Network distance to the host */
    int setNetworkDistance(int distance);
    int getNetworkDistance();

    /* Interface Information */
    int setInterface(NetworkInterface *val);
    NetworkInterface *getInterface();

    /* Packet information */
    int setIPv4(IPv4HeaderTemplate *hdr);
    int setIPv6(IPv6HeaderTemplate *hdr);
    int setTCP(TCPHeaderTemplate *hdr);
    int setICMPv4(ICMPv4HeaderTemplate *hdr);

    void reset();
    int getNextPacketBatch(vector<PacketElement *> &Packets);

};

#endif /* __TARGETHOST_H__ */
