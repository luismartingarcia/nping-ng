
/***************************************************************************
 * MACAddress.cc -- This class offers a generic representation for Ethernet*
 * MAC addresses.                                                          *
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

#include "MACAddress.h"

/** Standard constructor. Initializes the internal attributes of the object.
  * Basically it just performs a reset() operation. Check MACAddress::reset()
  * documentation for details. */
MACAddress::MACAddress(){
  this->reset();
}

/** Standard destructor. It doesn't free anything (as there is no dynamically
  * allocated data inside the object), but sets the object state to the initial
  * state, through a reset() call. Check MACAddress::reset() documentation for
  * details. */
MACAddress::~MACAddress(){
  this->reset();
}

/** Sets the object to a safe initial state. Basically all structures that
  * hold address information are zeroed. */
void MACAddress::reset(){
  memset(this->address, 0, MACADDRESS_LEN);
  this->addr_set=false;
  return;
} /* End of reset() */


/** Determines if two IP addresses are equal. */
bool MACAddress::operator==(const MACAddress& other) const {
  for(int i=0; i<MACADDRESS_LEN; i++){
    if(this->address[i] != other.address[i]){
      return false; 
    }
  }
  return true;
} /* End of operator== */


/* Returns true if a MAC address has been set, false otherwise. */
bool MACAddress::is_set(){
  return this->addr_set;
} /* End of is_set() */

/** Receives a MAC address as a string of format 00:13:01:e6:c7:ae or
 *  00-13-01-e6-c7-ae and stores in targetbuff the 6 corresponding bytes.
 *  The "txt" parameter may take the special value "rand" or "random",
 *  in which case, 6 random bytes will be stored in "targetbuff".
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.
 *  Buffer targetbuff is NOT modified if "txt" does not have the propper
 *  format */
int MACAddress::setAddress_str(const char *txt){
  u8 mac_data[6];
  char tmphex[3];
  int i=0, j=0;

  if(txt==NULL)
    return OP_FAILURE;

  /* Set up a random MAC if user requested so. */
  if( !strcasecmp(optarg, "rand") || !strcasecmp(optarg, "random") ){
    get_random_bytes(this->address, MACADDRESS_LEN);
    this->addr_set=true;
    return OP_SUCCESS;
  /* Or set it to FF:FF:FF:FF:FF:FF if user chose broadcast */
  }else if( !strcasecmp(optarg, "broadcast") || !strcasecmp(optarg, "bcast") ){
    memset(this->address, 0xFF, MACADDRESS_LEN);
    this->addr_set=true;
    return OP_SUCCESS;
  }

  /* Array should look like  00:13:01:e6:c7:ae  or  00-13-01-e6-c7-ae
     Array positions:        01234567890123456      01234567890123456  */
  if( strlen(txt)!=17 )
    return OP_FAILURE;
  /* Check MAC has the correct ':' or '-' characters */
  if( (txt[2]!=':' && txt[2]!='-') || (txt[5]!=':' && txt[5]!='-')   ||
      (txt[8]!=':' && txt[8]!='-') || (txt[11]!=':' && txt[11]!='-') ||
      (txt[14]!=':' && txt[14]!='-') )
      return OP_FAILURE;

  /* Convert txt into actual bytes */
  for(i=0, j=0; i<6; i++, j+=3 ){
    if( !isxdigit(txt[j]) || !isxdigit(txt[j+1]) )
        return OP_FAILURE;
    tmphex[0] = txt[j];
    tmphex[1] = txt[j+1];
    tmphex[2] = '\0';
    mac_data[i] = (u8) strtol(tmphex, NULL, 16);
  }
  memcpy(this->address, mac_data, MACADDRESS_LEN);
  this->addr_set=true;
  return OP_SUCCESS;
} /* End of setAddress_str() */


char *MACAddress::getAddress_str() const{
  static char macinfo[24];
  memset(macinfo, 0, 24);
  sprintf(macinfo,"%02X:%02X:%02X:%02X:%02X:%02X",
          this->address[0],this->address[1],this->address[2],
          this->address[3],this->address[4],this->address[5]);
  return macinfo;
} /* End of MACtoa() */


int MACAddress::setAddress_bin(const u8 *binbuff){
  assert(binbuff!=NULL);
  for(int i=0; i<MACADDRESS_LEN; i++){
    this->address[i]=binbuff[i];
  }
  this->addr_set=true;
  return OP_SUCCESS;
} /* End of setAddress_bin() */


int MACAddress::getAddress_bin(u8 *result){
  assert(result!=NULL);
  for(int i=0; i<MACADDRESS_LEN; i++){
    result[i]=this->address[i];
  }
  return OP_SUCCESS;
} /* End of getAddress_bin() */


const u8* MACAddress::getAddress_bin() const {
  return this->address;
} /* End of setAddress_bin() */








