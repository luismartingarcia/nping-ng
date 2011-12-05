
/***************************************************************************
 * NetworkInterface.cc -- This class represents a system's network         *
 * interface. It provides methods to store and access things like device   *
 * name, MAC address, device type, etc.                                    *
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

#include "NetworkInterface.h"


NetworkInterface::NetworkInterface(){
  this->reset();
} /* End of NetworkInterface constructor */


NetworkInterface::NetworkInterface(struct interface_info nfo){
  this->iface=nfo;
} /* End of NetworkInterface constructor */


NetworkInterface::~NetworkInterface(){

} /* End of NetworkInterface destructor */


void NetworkInterface::reset(){
  memset(&(this->iface), 0, sizeof(struct interface_info));
  this->associated_hosts=0;
} /* End of reset() */


/* Returns the name of the interface. It does not contain alias info. /*/
const char *NetworkInterface::getName(){
  return this->iface.devname;
} /* End of getName() */


/* Returns the type of the interface. Returned type will be one of:
 * devt_ethernet, devt_loopback, devt_p2p, devt_other. Those types are
 * defined in libnetutil. */
int NetworkInterface::getType(){
  return this->iface.device_type;
} /* End of getType() */


/* Returns the MAC address of the device. None that if the interface type
 * is not devt_ethernet, the returned result is unspecified. Therefore, the
 * caller must ensure that the device is an Ethernet interface before calling
 * this method.*/
MACAddress NetworkInterface::getAddress(){
  MACAddress mac;
  mac.setAddress_bin(this->iface.mac);
  return mac;
} /* End of getAddress() */

/* This provides a minor optimization for ProbeEngine. If we know how many
 * hosts are associated with a given interface, we can easily decide if we
 * can build a BPF filter that mentions host addresses explicitly or we
 * have to build a generic filter and discard packets later. If we didn't have
 * this variable, for every interface, we'd have to traverse the list of
 * hosts, counting how many are there. */
int NetworkInterface::addAssociatedHost(){
  this->associated_hosts++;
  return OP_SUCCESS;
} /* End of addAssociatedHost() */


/* Returns the number of TargetHosts associated with this interface. */
u32 NetworkInterface::associatedHosts(){
  return this->associated_hosts;
} /* End of associatedHosts() */
