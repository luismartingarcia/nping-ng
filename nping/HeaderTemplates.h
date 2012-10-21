
/***************************************************************************
 * HeaderTemplates.h --                                                    *
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

 #ifndef __HEADERTEMPLATES_H__
 #define __HEADERTEMPLATES_H__ 1

#include "ProtoField.h"
#include <vector>
using namespace std;

/******************************************************************************
 * DEFAULT PROTOCOL FIELD VALUES                                              *
 ******************************************************************************/

/* ARP */
#define DEFAULT_ARP_HTYPE (HDR_ETH10MB) /* Default hardware type: Ethernet */
#define DEFAULT_ARP_PTYPE 0x0800        /* Default protocol type: IPv4     */
#define DEFAULT_ARP_HADDRLEN 6          /* Length of Ethernet MAC addrs    */
#define DEFAULT_ARP_PADDRLEN 4          /* Length of IPv4 addresses        */
#define DEFAULT_ARP_OP (OP_ARP_REQUEST) /* Default operation: ARP_REQUEST  */

/* IPv4 */
#define DEFAULT_IPv4_TTL 64             /* Default IPv4 Time To Live        */
#define DEFAULT_IPv4_TOS 0              /* Default IPv4 Type of Service     */
#define DEFAULT_IPv4_FRAG_OFFSET 0      /* Default IPv4 Fragment Offset     */
#define DEFAULT_IPv4_FLAG_RF false      /* Default IPv4 Reserved flag       */
#define DEFAULT_IPv4_FLAG_DF false      /* Default IPv4 Don't Fragment flag */
#define DEFAULT_IPv4_FLAG_MF false      /* Default IPv4 More Fragments flag */

/* IPv6 */
#define DEFAULT_IPv6_TCLASS 0           /* Default IPv6 Traffic Class       */
#define DEFAULT_IPv6_FLOW 0             /* Default IPv6 Flow Label          */
#define DEFAULT_IPv6_HOPLIMIT 64        /* Default IPv6 Hop Limit           */

/* TCP */
#define DEFAULT_TCP_TARGET_PORT 80      /* Default target port              */
#define DEFAULT_TCP_ACKNOWLEDGMENT 0    /* Default ACK number               */
#define DEFAULT_TCP_WINDOW_SIZE 1480    /* Default TCP Window size          */
#define DEFAULT_TCP_OFFSET 5            /* Default offset (TCP header size) */
#define DEFAULT_TCP_FLAGS 0x02          /* Default TCP Flags (SYN)          */
#define DEFAULT_TCP_URGENT_POINTER 0    /* Default urgent pointer */

/* UDP */
/* Note: Source and target ports for UDP are based on research by David     */
/* Fifield http://www.bamsoftware.com/wiki/Nmap/EffectivenessOfPingProbes   */
#define DEFAULT_UDP_TARGET_PORT 40125   /* Default UDP target port          */
#define DEFAULT_UDP_SOURCE_PORT 53      /* Default UDP source port          */

/* ICMPv4 */
#define DEFAULT_ICMPv4_TYPE 8           /* Default msg type = Echo request  */
#define DEFAULT_ICMPv4_CODE 0           /* Default message code             */

/* ICMPv6 */
#define DEFAULT_ICMPv6_TYPE 128         /* Default msg type = Echo request  */
#define DEFAULT_ICMPv6_CODE 0           /* Default message code             */

class HeaderTemplate{
  public:
    HeaderTemplate();
    ~HeaderTemplate();
};


class EthernetHeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_mac dst;   /* Destination address         */
    ProtoField_mac src;   /* Source address              */
    ProtoField_u16 type;  /* Ether type                  */

    EthernetHeaderTemplate();
    ~EthernetHeaderTemplate();
    void reset();
};


class ARPHeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u16 htype;   /* Hardware type             */
    ProtoField_u16 ptype;   /* Protocol type             */
    ProtoField_u8 haddrlen; /* Hardware address length   */
    ProtoField_u8 paddrlen; /* Protocol address length   */
    ProtoField_u16 op;      /* ARP operation code        */
    ProtoField_mac sha;     /* Sender hardware address   */
    ProtoField_inaddr spa;  /* Sender protocol address   */
    ProtoField_mac tha;     /* Target hardware address   */
    ProtoField_inaddr tpa;  /* Target protocol address   */

    ARPHeaderTemplate();
    ~ARPHeaderTemplate();
    void reset();
};


class IPv4HeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u8 tos;    /* Type of Service             */
    ProtoField_u16 id;    /* Identification              */
    ProtoField_bool rf;   /* Reserved flag               */
    ProtoField_bool df;   /* Don't Fragment flag         */
    ProtoField_bool mf;   /* More Fragments flag         */
    ProtoField_u16 off;   /* Fragment Offset             */
    ProtoField_u16 csum;  /* Checksum                    */
    ProtoField_u8 ttl;    /* Time to Live                */
    ProtoField_u8 nh;     /* Next Header                 */
    ProtoField_buff opts; /* IP Options                  */

    IPv4HeaderTemplate();
    ~IPv4HeaderTemplate();
    void reset();
};


class IPv6HeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u8 tclass;  /* Traffic Class               */
    ProtoField_u32 flow ;  /* Flow Level                  */
    ProtoField_u8 nh;      /* Next Header                 */
    ProtoField_u8 hlim;    /* Hop Limit                   */

    IPv6HeaderTemplate();
    ~IPv6HeaderTemplate();
    void reset();
};


class TCPHeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u16 sport;  /* Source port                 */
    ProtoField_u16 dport;  /* Destination port            */
    ProtoField_u32 seq;    /* Sequence number             */
    ProtoField_u32 ack;    /* Acknowledgement number      */
    ProtoField_u8 off;     /* Data offset                 */
    ProtoField_u8 flags;   /* Flags                       */
    ProtoField_u16 win;    /* Window size                 */
    ProtoField_u16 csum;   /* Checksum                    */
    ProtoField_u16 urp;    /* Urgent pointer              */

    TCPHeaderTemplate();
    ~TCPHeaderTemplate();
    void reset();
};


class UDPHeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u16 sport;  /* Source port                 */
    ProtoField_u16 dport;  /* Destination port            */
    ProtoField_u16 len;    /* Length                      */
    ProtoField_u16 csum;   /* Checksum                    */

    UDPHeaderTemplate();
    ~UDPHeaderTemplate();
    void reset();
};


class ICMPv4HeaderTemplate : public HeaderTemplate{
  public:

    /* Common ICMP fields */
    ProtoField_u8 type;              /* ICMP message type          */
    ProtoField_u8 code;              /* ICMP message code          */
    ProtoField_u16 csum;             /* Checksum                   */

    /* Fields shared by ICMP Echo, Timestamp, mask, etc. */
    ProtoField_u16 id;               /* Identifier                 */
    ProtoField_u16 seq;              /* Sequence number            */

    /* ICMP Parameter Problem */
    ProtoField_u8 pointer;           /* Pointer                    */

    /* ICMP Redirect */
    ProtoField_inaddr redir_addr;    /* Gateway Internet Address   */

    /* ICMP Timestamp */
    ProtoField_u32 ts_orig;          /* Originate timestamp        */
    ProtoField_u32 ts_rx;            /* Receive  timestamp         */
    ProtoField_u32 ts_tx;            /* Transmit timestamp         */

    /* ICMP Router Advertisement */
    ProtoField_u8 numaddrs;          /* Number of router addresses */
    ProtoField_u8 addrsize;          /* Length of each address     */
    ProtoField_u16 lifetime;         /* Advertisement lifetime     */
    vector<ProtoField_inaddr> routeraddrs; /* Router addresses     */
    vector<ProtoField_u32> preflevels;     /* Preference levels    */

    /* ICMP Netmask */
    ProtoField_inaddr mask;          /* Address mask               */

    /* ICMP Traceroute */
    ProtoField_u16 outbound_hops;    /* Outbound hop count         */
    ProtoField_u16 return_hops;      /* Return hop count           */
    ProtoField_u32 speed;            /* Output link speed          */
    ProtoField_u32 mtu;              /* Output link MTU            */

    ICMPv4HeaderTemplate();
    ~ICMPv4HeaderTemplate();
    void reset();
};


class ICMPv6HeaderTemplate : public HeaderTemplate{
  public:

    /* Common ICMP fields */
    ProtoField_u8 type;              /* ICMP message type          */
    ProtoField_u8 code;              /* ICMP message code          */
    ProtoField_u16 csum;             /* Checksum                   */

    /* Echo requests/replies */
    ProtoField_u16 id;               /* Identifier                 */
    ProtoField_u16 seq;              /* Sequence number            */

    /* Packet too big */
    ProtoField_u32 mtu;              /* MTU that caused the error  */

    /* Parameter problem */
    ProtoField_u32 pointer;          /* Offset to the error        */

    /* Router advertisements */
    ProtoField_u8 ra_hlim;          /* Offset to the error           */
    ProtoField_bool ra_M;           /* Managed Address Config Flag   */
    ProtoField_bool ra_O;           /* Other Configuration Flag      */
    ProtoField_bool ra_H;           /* Mobile Home Agent Flag        */
    ProtoField_bool ra_Prf;         /* Router Selection Preferences  */
    ProtoField_bool ra_P;           /* Neighbor Discovery Proxy Flag */
    ProtoField_bool ra_R1;          /* Reserved flag                 */
    ProtoField_bool ra_R2;          /* Reserved flag                 */
    ProtoField_u16 ra_lifetime;     /* Router lifetime               */
    ProtoField_u32 ra_reachtime;    /* Reachable time                */
    ProtoField_u32 ra_retrtimer;    /* Retransmission timer           */

    /* Neighbor advertisement */
    ProtoField_bool na_R;           /* Router flag                   */
    ProtoField_bool na_S;           /* Solicited flag                */
    ProtoField_bool na_O;           /* Override flag                 */
    ProtoField_in6addr na_addr;     /* Target address                */

    /* Neighbor solicitation */
    ProtoField_in6addr ns_addr;     /* Target address                */

    ICMPv6HeaderTemplate();
    ~ICMPv6HeaderTemplate();
    void reset();
};


 #endif /* __HEADERTEMPLATES_H__ */
