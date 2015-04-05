
/***************************************************************************
 * ICMPv6RRBody.h -- The ICMPv6RRBody Class represents an ICMP version 6   *
 * Router Renumbering message body. It contains methods to set any header  *
 * field. In general, these  methods do error checkings and byte order     *
 * conversions.                                                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2014 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/
/* This code was originally part of the Nping tool.                        */

#include "ICMPv6RRBody.h"
#include "ICMPv6Header.h"


ICMPv6RRBody::ICMPv6RRBody(u8 icmp6code){
  this->reset();
  this->code=icmp6code;
  switch(icmp6code){
      case ICMPv6_RTRRENUM_COMMAND:
        this->length=ICMPv6_RR_MATCH_PREFIX_LEN;
      break;
      case ICMPv6_RTRRENUM_RESULT:
        this->length=ICMPv6_RR_RESULT_MSG_LEN;
      break;
      case ICMPv6_RTRRENUM_SEQ_RESET:
        this->length=0;
      break;
      default:
        this->length=0;
      break;
  }
} /* End of ICMPv6RRBody constructor */


ICMPv6RRBody::~ICMPv6RRBody() {

} /* End of ICMPv6RRBody destructor */


/** Sets every class attribute to zero */
void ICMPv6RRBody::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv6_rr_body_t));
  h_mp = (rr_match_prefix_t *)this->h.data;
  h_up = (rr_use_prefix_t   *)((u8*)this->h.data+ICMPv6_RR_MATCH_PREFIX_LEN);
  h_r  = (rr_result_msg_t   *)this->h.data;
  this->code=ICMPv6_RTRRENUM_COMMAND;
  this->length=ICMPv6_RR_MATCH_PREFIX_LEN;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv6RRBody::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv6RRBody class is able to hold a maximum of
  * sizeof(nping_icmpv6_rr_body_t) bytes. If the supplied buffer is longer than
  * that, only the first sizeof(nping_icmpv6_rr_body_t) bytes will be stored in
  * the internal buffer.
  * @warning Supplied len MUST be at least ICMPv6_RR_MIN_LENGTH bytes
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv6RRBody::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMPv6_RR_MIN_LENGTH){
    return OP_FAILURE;
  }else{
    int stored_len = MIN( sizeof(nping_icmpv6_rr_body_t), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int ICMPv6RRBody::protocol_id() const {
    return HEADER_TYPE_ICMPv6_RRBODY;
} /* End of protocol_id() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int ICMPv6RRBody::print(FILE *output, int detail) const {
  struct in6_addr addr;
  static char ipstring[256];
  fprintf(output, "RRBody[");

  if(this->code==ICMPv6_RTRRENUM_COMMAND){
    if(this->length>=ICMPv6_RR_MATCH_PREFIX_LEN){
      addr=this->getMatchPrefix();
      inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
      fprintf(output, "match=%s/%d/%d/%d", ipstring, this->getMatchedLength(),
              this->getMinLength(), this->getMaxLength());
    }
    if(this->length>=ICMPv6_RR_MATCH_PREFIX_LEN+ICMPv6_RR_USE_PREFIX_LEN){
      addr=this->getUsePrefix();
      inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
      fprintf(output, " use=%s/%d/%d", ipstring, this->getUseLength(),
              this->getKeepLength());
    }
  }else if(this->code==ICMPv6_RTRRENUM_RESULT){
      addr=this->getMatchedPrefix();
      inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
      fprintf(output, "matched=%s/%d idx=%d", ipstring, this->getMatchedLength(),
              this->getInterfaceIndex());
  }else if(this->code==ICMPv6_RTRRENUM_SEQ_RESET){
    fprintf(output, "Seq Reset");
  }

  fprintf(output, "]");

  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/* This function should be called when we detect that we need to include a
 * use-prefix header after the Match-prefix one. Basically, it only adjusts the
 * object's length variable so we have space to hold the use-prefix. The
 * method is declared private because it is called by the setters that set
 * protocol fields that are present in a use-prefix header. */
int ICMPv6RRBody::include_use_prefix(){
  this->length=ICMPv6_RR_MATCH_PREFIX_LEN+ICMPv6_RR_USE_PREFIX_LEN;
  return OP_SUCCESS;
} /* End of include_use_prefix() */


/** Set Match Prefix OP Code */
int ICMPv6RRBody::setOpCode(u8 val){
  this->h_mp->op_code=val;
  return OP_SUCCESS;
} /* End of setOpCode() */


/** Returns Match Prefix OP Code */
u8 ICMPv6RRBody::getOpCode() const {
  return this->h_mp->op_code;
} /* End of getOpCode() */


/** Set Match Prefix OP Length */
int ICMPv6RRBody::setOpLength(u8 val){
  this->h_mp->op_length=val;
  return OP_SUCCESS;
} /* End of setOpLength() */


/** Returns Match Prefix OP Length */
u8 ICMPv6RRBody::getOpLength() const {
  return this->h_mp->op_length;
} /* End of getOpLength() */


/** Set Match Prefix Ordinal */
int ICMPv6RRBody::setOrdinal(u8 val){
  if(this->code==ICMPv6_RTRRENUM_RESULT){
    this->h_r->ordinal=val;
  }else{
    this->h_mp->ordinal=val;
  }
  return OP_SUCCESS;
} /* End of setOrdinal() */


/** Returns Match Prefix Ordinal */
u8 ICMPv6RRBody::getOrdinal() const {
  if(this->code==ICMPv6_RTRRENUM_RESULT){
    return this->h_r->ordinal;
  }else{
    return this->h_mp->ordinal;
  }
} /* End of getOrdinal() */


/** Set Match Prefix Match Length */
int ICMPv6RRBody::setMatchLength(u8 val){
  this->h_mp->match_length=val;
  return OP_SUCCESS;
} /* End of setMatchLength() */


/** Returns Match Prefix Match Length */
u8 ICMPv6RRBody::getMatchLength() const {
  return this->h_mp->match_length;
} /* End of getMatchLength() */


/** Set Match Prefix Max Length */
int ICMPv6RRBody::setMaxLength(u8 val){
  this->h_mp->max_length=val;
  return OP_SUCCESS;
} /* End of setMaxLength() */


/** Returns Match Prefix Max Length */
u8 ICMPv6RRBody::getMaxLength() const {
  return this->h_mp->max_length;
} /* End of getMaxLength() */


/** Set Match Prefix Min Length */
int ICMPv6RRBody::setMinLength(u8 val){
  this->h_mp->min_length=val;
  return OP_SUCCESS;
} /* End of setMinLength() */


/** Returns Match Prefix Min Length */
u8 ICMPv6RRBody::getMinLength() const {
  return this->h_mp->min_length;
} /* End of getMinLength() */


/** Set Match Prefix */
int ICMPv6RRBody::setMatchPrefix(struct in6_addr addr){
  memcpy(this->h_mp->match_prefix, addr.s6_addr, 16);
  return OP_SUCCESS;
} /* End of setMatchPrefix() */


/** Returns match prefix */
struct in6_addr ICMPv6RRBody::getMatchPrefix() const{
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));
  memcpy(addr.s6_addr, this->h_mp->match_prefix, 16);
  return addr;
} /* End of getMatchPrefix() */

/** Set Use-Prefix Use Length */
int ICMPv6RRBody::setUseLength(u8 val){
  this->include_use_prefix();
  this->h_up->use_len=val;
  return OP_SUCCESS;
} /* End of setUseLength() */


/** Returns Use-Prefix Use Length */
u8 ICMPv6RRBody::getUseLength() const {
  return this->h_up->use_len;
} /* End of getUseLength() */


/** Set Use-Prefix Keep Length */
int ICMPv6RRBody::setKeepLength(u8 val){
  this->include_use_prefix();
  this->h_up->keep_len=val;
  return OP_SUCCESS;
} /* End of setKeepLength() */


/** Returns Use-Prefix Keep Length */
u8 ICMPv6RRBody::getKeepLength() const {
  return this->h_up->keep_len;
} /* End of getKeepLength() */


/** Set Use-Prefix Flag Mask */
int ICMPv6RRBody::setFlagMask(u8 val){
  this->include_use_prefix();
  this->h_up->flag_mask=val;
  return OP_SUCCESS;
} /* End of setFlagMask() */


/** Returns Use-Prefix Flag Mask */
u8 ICMPv6RRBody::getFlagMask() const {
  return this->h_up->flag_mask;
} /* End of getFlagMask() */


/** Set Use-Prefix Valid Lifetime */
int ICMPv6RRBody::setValidLifetime(u32 val){
  this->include_use_prefix();
  this->h_up->valid_lifetime=htonl(val);
  return OP_SUCCESS;
} /* End of setValidLifetime() */


/** Returns Use-Prefix Valid Lifetime */
u32 ICMPv6RRBody::getValidLifetime() const {
  return ntohl(this->h_up->valid_lifetime);
} /* End of getValidLifetime() */


/** Set Use-Prefix Preferred Lifetime */
int ICMPv6RRBody::setPreferredLifetime(u32 val){
  this->include_use_prefix();
  this->h_up->preferred_lifetime=htonl(val);
  return OP_SUCCESS;
} /* End of setPreferredLifetime() */


/** Returns Use-Prefix Preferred Lifetime */
u32 ICMPv6RRBody::getPreferredLifetime() const {
  return ntohl(this->h_up->preferred_lifetime);
} /* End of getPreferredLifetime() */


/** Set Use Prefix */
int ICMPv6RRBody::setUsePrefix(struct in6_addr addr){
  this->include_use_prefix();
  memcpy(this->h_up->use_prefix, addr.s6_addr, 16);
  return OP_SUCCESS;
} /* End of setUsePrefix() */


/** Returns Use Prefix */
struct in6_addr ICMPv6RRBody::getUsePrefix() const{
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));
  memcpy(addr.s6_addr, this->h_up->use_prefix, 16);
  return addr;
} /* End of getUsePrefix() */


/** Set Result Matched Length */
int ICMPv6RRBody::setMatchedLength(u8 val){
  this->h_r->matched_length=val;
  return OP_SUCCESS;
} /* End of setMatchedLength() */


/** Returns Result Matched Length */
u8 ICMPv6RRBody::getMatchedLength() const {
  return this->h_r->matched_length;
} /* End of getMatchedLength() */


/** Set Result Matched Length */
int ICMPv6RRBody::setInterfaceIndex(u32 val){
  this->h_r->interface_index=htonl(val);
  return OP_SUCCESS;
} /* End of setInterfaceIndex() */


/** Returns Result Matched Length */
u32 ICMPv6RRBody::getInterfaceIndex() const {
  return ntohl(this->h_r->interface_index);
} /* End of getInterfaceIndex() */


/** Set Result Matched Prefix */
int ICMPv6RRBody::setMatchedPrefix(struct in6_addr addr){
  memcpy(this->h_r->matched_prefix, addr.s6_addr, 16);
  return OP_SUCCESS;
} /* End of setMatchedPrefix() */


/** Returns Result Matched Prefix */
struct in6_addr ICMPv6RRBody::getMatchedPrefix() const{
  struct in6_addr addr;
  memset(&addr, 0, sizeof(struct in6_addr));
  memcpy(addr.s6_addr, this->h_r->matched_prefix, 16);
  return addr;
} /* End of getMatchedPrefix() */
