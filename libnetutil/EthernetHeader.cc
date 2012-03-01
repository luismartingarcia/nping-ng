
/***************************************************************************
 * EthernetHeader.cc -- The EthernetHeader Class represents an Ethernet    *
 * header and footer. It contains methods to set the different header      *
 * fields. These methods tipically perform the necessary error checks and  *
 * byte order conversions.                                                 *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/
/* This code was originally part of the Nping tool.                        */

#include "EthernetHeader.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
EthernetHeader::EthernetHeader(){
  this->reset();
} /* End of EthernetHeader constructor */


EthernetHeader::~EthernetHeader(){

} /* End of EthernetHeader destructor */


/** Sets every attribute to its default value */
void EthernetHeader::reset(){
  memset(&this->h, 0, sizeof(nping_eth_hdr_t));
  this->length=ETH_HEADER_LEN;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * EthernetHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The EthernetHeader class is able to hold a maximum of 14 bytes.
  * If the supplied buffer is longer than that, only the first 14 bytes will be
  * stored in the internal buffer.
  * @warning Supplied len MUST be at least 14 bytes (Ethernet header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int EthernetHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ETH_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=ETH_HEADER_LEN;
    memcpy(&(this->h), buf, ETH_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int EthernetHeader::protocol_id() const {
    return HEADER_TYPE_ETHERNET;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int EthernetHeader::validate(){
  if( this->length!=ETH_HEADER_LEN)
    return OP_FAILURE;
  else
    return ETH_HEADER_LEN;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int EthernetHeader::print(FILE *output, int detail) const {

    fprintf(output, "Eth[");

    for(int i=0; i<6; i++){
        fprintf(output, "%02x", this->h.eth_smac[i]);
        if(i<5)
          fprintf(output, ":");
    }

    fprintf(output, " > ");

    for(int i=0; i<6; i++){
        fprintf(output, "%02x", this->h.eth_dmac[i]);
        if(i<5)
          fprintf(output, ":");
    }

    if(detail>=PRINT_DETAIL_MED)
        fprintf(output, " Type=%04x", this->getEtherType());

    fprintf(output, "]");

  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Sets Source MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setSrcMAC(const u8 *m){
  if(m==NULL)
    netutil_fatal("EthernetHeader::setSrcMAC(u8*): NULL value supplied ");
  memcpy(h.eth_smac, m, 6);
  return OP_SUCCESS;
} /* End of setSrcMAC() */


/** Returns source port in HOST byte order
 *  @warning Returned pointer points directly to a Class internal buffer. If
 *  contents are changed, the instance of the class will be affected. */
const u8* EthernetHeader::getSrcMAC() const {
  return this->h.eth_smac;
} /* End of getSrcMAC() */


/** Sets Destination MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setDstMAC(u8 *m){
  if(m==NULL)
    netutil_fatal("EthernetHeader::setDstMAC(u8 *): NULL value supplied ");
  memcpy(h.eth_dmac, m, 6);
  return OP_SUCCESS;
} /* End of setDstMAC() */



/** Returns destination port in HOST byte order */
const u8 *EthernetHeader::getDstMAC() const {
  return this->h.eth_dmac;
} /* End of getDstMAC() */


int EthernetHeader::setEtherType(u16 val){
  h.eth_type=htons(val);
  return OP_SUCCESS;
} /* End of setEtherType() */


/** Returns destination port in HOST byte order */
const u16 EthernetHeader::getEtherType() const {
  return ntohs(this->h.eth_type);
} /* End of getEtherType() */

