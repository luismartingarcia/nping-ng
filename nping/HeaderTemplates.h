
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



/******************************************************************************
 * DEFAULT PROTOCOL FIELD VALUES                                              *
 ******************************************************************************/

/* IPv4 */
#define DEFAULT_IPv4_TTL 64             /* Default IPv4 Time To Live        */
#define DEFAULT_IPv4_TOS 0              /* Default IPv4 Type of Service     */
#define DEFAULT_IPv4_FRAG_OFFSET 0      /* Default IPv4 Fragment Offset     */
#define DEFAULT_IPv4_FLAG_RF false      /* Default IPv4 Reserved flag       */
#define DEFAULT_IPv4_FLAG_DF false      /* Default IPv4 Don't Fragment flag */
#define DEFAULT_IPv4_FLAG_MF false      /* Default IPv4 More Fragments flag */


/* IPv6 */

/* TCP */
#define DEFAULT_TCP_TARGET_PORT 80      /* Default target port              */
#define DEFAULT_TCP_ACKNOWLEDGMENT 0    /* Default ACK number               */
#define DEFAULT_TCP_WINDOW_SIZE 1480    /* Default TCP Window size          */
#define DEFAULT_TCP_OFFSET 5            /* Default offset (TCP header size) */
#define DEFAULT_TCP_FLAGS 0x20          /* Default TCP Flags (SYN)          */
#define DEFAULT_TCP_URGENT_POINTER 0    /* Default urgent pointer */

/* UDP */

/* ICMPv4 */

/* ICMPv6 */

class HeaderTemplate{
  public:
    HeaderTemplate();
    ~HeaderTemplate();
};


class IPv4HeaderTemplate : public HeaderTemplate{
  public:
    ProtoField_u8 tos;    /* Type of Service             */
    ProtoField_u16 id;    /* Identification              */
    ProtoField_bool rf;   /* Reserved flag               */
    ProtoField_bool df;   /* Don't Fragment flag         */
    ProtoField_bool mf;   /* More Fragments flag         */
    ProtoField_u16 off;   /* Fragment Offset             */
    ProtoField_u8 ttl;    /* Time to Live                */
    ProtoField_u8 nh;     /* Next Header                 */

    IPv4HeaderTemplate();
    ~IPv4HeaderTemplate();
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


 #endif /* __HEADERTEMPLATES_H__ */
