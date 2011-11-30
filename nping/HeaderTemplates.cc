
/***************************************************************************
 * HeaderTemplates.cc --                                                   *
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

#include "HeaderTemplates.h"


/******************************************************************************
 * GENERIC HeaderTemplate CLASS                                               *
 ******************************************************************************/

HeaderTemplate::HeaderTemplate(){

} /* End of HeaderTemplate constructor */


HeaderTemplate::~HeaderTemplate(){

} /* End of HeaderTemplate destructor */





/******************************************************************************
 * IPv4PHeaderTemplate Class                                                    *
 ******************************************************************************/

IPv4HeaderTemplate::IPv4HeaderTemplate(){
  this->reset();
} /* End of IPv4HeaderTemplate constructor */


IPv4HeaderTemplate::~IPv4HeaderTemplate(){

} /* End of IPv4HeaderTemplate destructor */


/* This method returns the object to its default state. The reset() method is
 * very important because it initializes IPv4 header fields with default values
 * that will affect the final packets that Nping produces. However, note that
 * the values set here may be overridden by NpingOps if necessary (when the
 * user supplies his own values or when we have special restrictions) */
void IPv4HeaderTemplate::reset(){

  /* Type of Service */
  this->tos.setConstant(DEFAULT_IPv4_TOS);

  /* Identification */
  this->id.setBehavior(FIELD_TYPE_INCREMENTAL);
  this->id.setStartValue(get_random_u16());

  /* Flags */
  this->rf.setConstant(DEFAULT_IPv4_FLAG_RF);
  this->df.setConstant(DEFAULT_IPv4_FLAG_DF);
  this->mf.setConstant(DEFAULT_IPv4_FLAG_MF);

  /* Fragment Offset */
  this->off.setConstant(DEFAULT_IPv4_FRAG_OFFSET);

  /* Time To Live */
  this->ttl.setConstant(DEFAULT_IPv4_TTL);

  // this->nh.setConstant() The Next header is unset on purpose.
} /* End of reset() */


/******************************************************************************
 * IPv6HeaderTemplate Class                                                    *
 ******************************************************************************/

IPv6HeaderTemplate::IPv6HeaderTemplate(){
  this->reset();
} /* End of IPv6PHeaderTemplate constructor */


IPv6HeaderTemplate::~IPv6HeaderTemplate(){

} /* End of IPv6PHeaderTemplate destructor */


/* This method returns the object to its default state. The reset() method is
 * very important because it initializes IPv4 header fields with default values
 * that will affect the final packets that Nping produces. However, note that
 * the values set here may be overridden by NpingOps if necessary (when the
 * user supplies his own values or when we have special restrictions) */
void IPv6HeaderTemplate::reset(){
  /* Traffic Class */
  this->tclass.setConstant(DEFAULT_IPv6_TCLASS);
  /* Flow Label */
  this->flow.setConstant(DEFAULT_IPv6_FLOW);
  /* Time To Live */
  this->hlim.setConstant(DEFAULT_IPv6_HOPLIMIT);
  // this->nh.setConstant() The Next header is unset on purpose.
} /* End of reset() */

/******************************************************************************
 * TCPHeaderTemplate Class                                                    *
 ******************************************************************************/

TCPHeaderTemplate::TCPHeaderTemplate(){
  this->reset();
} /* End of TCPHeaderTemplate constructor */


TCPHeaderTemplate::~TCPHeaderTemplate(){

} /* End of TCPHeaderTemplate destructor */


/* This method returns the object to its default state. The reset() method is
 * very important because it initializes TCP header fields with default values
 * that will affect the final packets that Nping produces. However, note that
 * the values set here may be overridden by NpingOps if necessary (when the
 * user supplies his own values or when we have special restrictions, like
 * in Echo Client Mode, where the source port cannot be the same as the
 * NEP port number in use */
void TCPHeaderTemplate::reset(){

  /* Source Port. We chose an incremental random port number, higher  than 1024. */
  this->sport.setBehavior(FIELD_TYPE_INCREMENTAL);
  u16 start_port=1024 + (get_random_u16()%(65535-1024))/2;
  this->sport.setStartValue(start_port);
  this->sport.setMaxIncrements(65535-start_port);
  /* Destination Port */
  this->dport.setBehavior(FIELD_TYPE_CONSTANT);
  this->dport.setStartValue(DEFAULT_TCP_TARGET_PORT);
  /* Sequence number */
  this->seq.setBehavior(FIELD_TYPE_INCREMENTAL);
  this->seq.setStartValue( get_random_u32() );
  /* Acknowledgement number */
  this->ack.setBehavior(FIELD_TYPE_CONSTANT);
  this->ack.setStartValue(DEFAULT_TCP_ACKNOWLEDGMENT);
  /* Offset (TCP header length in 32-bit words) */
  this->off.setBehavior(FIELD_TYPE_CONSTANT);
  this->off.setStartValue(DEFAULT_TCP_OFFSET);
  /* Flags */
  this->flags.setBehavior(FIELD_TYPE_CONSTANT);
  this->flags.setStartValue(DEFAULT_TCP_FLAGS);
  /* Window size */
  this->win.setBehavior(FIELD_TYPE_CONSTANT);
  this->win.setStartValue(DEFAULT_TCP_WINDOW_SIZE);
  /* Checksum */
  // We don't initialize the checksum so is_set() returns false
  /* Urgent pointer */
  this->urp.setBehavior(FIELD_TYPE_CONSTANT);
  this->urp.setStartValue(DEFAULT_TCP_URGENT_POINTER);

} /* End of reset() */



/******************************************************************************
 * ICMPv4HeaderTemplate Class                                                    *
 ******************************************************************************/

ICMPv4HeaderTemplate::ICMPv4HeaderTemplate(){
  this->reset();
} /* End of ICMPv4HeaderTemplate constructor */


ICMPv4HeaderTemplate::~ICMPv4HeaderTemplate(){

} /* End of ICMPv4HeaderTemplate destructor */


/* This method returns the object to its default state. The reset() method is
 * very important because it initializes ICMP header fields with default values
 * that will affect the final packets that Nping produces. However, note that
 * the values set here may be overridden by NpingOps if necessary */
void ICMPv4HeaderTemplate::reset(){

  this->type.setConstant(DEFAULT_ICMPv4_TYPE);
  this->code.setConstant(DEFAULT_ICMPv4_CODE);
  this->id.setConstant(get_random_u16());
  this->seq.setBehavior(FIELD_TYPE_INCREMENTAL);
  this->seq.setStartValue(0);

} /* End of reset() */