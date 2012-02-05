
/***************************************************************************
 * ProtoField.cc --                                                        *
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

#include "ProtoField.h"


/*****************************************************************************
 * ProtoField Class                                                          *
 *****************************************************************************/

ProtoField::ProtoField(){
  this->behavior=FIELD_TYPE_CONSTANT;
  this->increment_value=1;
  this->max_increments=0;
  this->increment_count=0;
  this->set=false;
} /* End of ProtoField constructor */


ProtoField::~ProtoField(){

} /* End of ProtoField destructor */


int ProtoField::setBehavior(int val){
  this->behavior=val;
  return OP_SUCCESS;
} /* End of setBehavior() */


int ProtoField::getBehavior(){
  return this->behavior;
} /* End of getBehavior() */


int ProtoField::setIncrementValue(u32 val){
  this->increment_value=val;
  return OP_SUCCESS;
} /* End of setIncrementValue() */


int ProtoField::setMaxIncrements(u32 val){
  this->max_increments=val;
  return OP_SUCCESS;
} /* End of setMaxIncrements() */


/* Returns true if an actual value for the field has been set explicitly. */
bool ProtoField::is_set(){
  return this->set;
} /* End of is_set() */


/*****************************************************************************
 * ProtoField_u8 Class                                                       *
 *****************************************************************************/

ProtoField_u8::ProtoField_u8(){
  this->start_value=0;
  this->current_value=0;
} /* End of ProtoField_u8 constructor */


ProtoField_u8::ProtoField_u8(u8 startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_u8 constructor */


ProtoField_u8::ProtoField_u8(u8 *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_u8 constructor */


ProtoField_u8::~ProtoField_u8(){

} /* End of ProtoField_u8 destructor */


int ProtoField_u8::setStartValue(u8 startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_u8::setDiscreteSet(u8 *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_u8::setConstant(u8 val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


u8 ProtoField_u8::getNextValue(){
  u8 return_val=0;
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      /* We don't check for overflows, the caller must ensure the increment
       * value is reasonable */
      return_val=this->current_value;

      if(max_increments>0 && increment_count>=max_increments){
        this->current_value=this->start_value;
        this->increment_count=0;
      }else{
        this->current_value += this->increment_value;
        this->increment_count++;
      }
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      return get_random_u8();
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return 0;
} /* End of getNextValue() */


/*****************************************************************************
 * ProtoField_u16 Class                                                       *
 *****************************************************************************/

ProtoField_u16::ProtoField_u16(){
  this->start_value=0;
  this->current_value=0;
} /* End of ProtoField_u16 constructor */


ProtoField_u16::ProtoField_u16(u16 startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_u16 constructor */


ProtoField_u16::ProtoField_u16(u16 *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_u16 constructor */


ProtoField_u16::~ProtoField_u16(){

} /* End of ProtoField_u16 destructor */


int ProtoField_u16::setStartValue(u16 startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_u16::setDiscreteSet(u16 *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_u16::setConstant(u16 val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


u16 ProtoField_u16::getNextValue(){
  u16 return_val=0;
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      /* We don't check for overflows, the caller must ensure the increment
       * value is reasonable */
      return_val=this->current_value;

      if(max_increments>0 && increment_count>=max_increments){
        this->current_value=this->start_value;
        this->increment_count=0;
      }else{
        this->current_value += this->increment_value;
        this->increment_count++;
      }
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      return get_random_u16();
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return 0;
} /* End of getNextValue() */


/*****************************************************************************
 * ProtoField_u32 Class                                                       *
 *****************************************************************************/

ProtoField_u32::ProtoField_u32(){
  this->start_value=0;
  this->current_value=0;
} /* End of ProtoField_u32 constructor */


ProtoField_u32::ProtoField_u32(u32 startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_u32 constructor */


ProtoField_u32::ProtoField_u32(u32 *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_u32 constructor */


ProtoField_u32::~ProtoField_u32(){

} /* End of ProtoField_u32 destructor */


int ProtoField_u32::setStartValue(u32 startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_u32::setDiscreteSet(u32 *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_u32::setConstant(u32 val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


u32 ProtoField_u32::getNextValue(){
  u32 return_val=0;
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      /* We don't check for overflows, the caller must ensure the increment
       * value is reasonable */
      return_val=this->current_value;

      if(max_increments>0 && increment_count>=max_increments){
        this->current_value=this->start_value;
        this->increment_count=0;
      }else{
        this->current_value += this->increment_value;
        this->increment_count++;
      }
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      return get_random_u32();
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return 0;
} /* End of getNextValue() */



/*****************************************************************************
 * ProtoField_bool Class                                                       *
 *****************************************************************************/

ProtoField_bool::ProtoField_bool(){
  this->start_value=false;
  this->current_value=false;
} /* End of ProtoField_bool constructor */


ProtoField_bool::ProtoField_bool(bool startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_bool constructor */


ProtoField_bool::ProtoField_bool(bool *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_bool constructor */


ProtoField_bool::~ProtoField_bool(){

} /* End of ProtoField_bool destructor */


int ProtoField_bool::setStartValue(bool startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_bool::setDiscreteSet(bool *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_bool::setConstant(bool val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


bool ProtoField_bool::getNextValue(){
  bool return_val=0;
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      return_val=this->current_value;
      this->current_value = !this->current_value;
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      return get_random_u8()%2;
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return 0;
} /* End of getNextValue() */



/*****************************************************************************
 * ProtoField_inaddr Class                                                   *
 *****************************************************************************/

ProtoField_inaddr::ProtoField_inaddr(){
  memset(&this->start_value, 0, sizeof(struct in_addr));
  memset(&this->current_value, 0, sizeof(struct in_addr));
} /* End of ProtoField_inaddr constructor */


ProtoField_inaddr::ProtoField_inaddr(struct in_addr startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_inaddr constructor */


ProtoField_inaddr::ProtoField_inaddr(struct in_addr *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_inaddr constructor */


ProtoField_inaddr::~ProtoField_inaddr(){

} /* End of ProtoField_inaddr destructor */


int ProtoField_inaddr::setStartValue(struct in_addr startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_inaddr::setDiscreteSet(struct in_addr *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_inaddr::setConstant(struct in_addr val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


struct in_addr ProtoField_inaddr::getNextValue(){
  struct in_addr return_val;
  memset(&return_val, 0, sizeof(struct in_addr));
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      return_val=this->current_value;
      this->current_value.s_addr = htonl( ntohl(this->current_value.s_addr)+1 );
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      return_val.s_addr=get_random_u32();
      return return_val;
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return return_val;
} /* End of getNextValue() */




/*****************************************************************************
 * ProtoField_mac Class                                                      *
 *****************************************************************************/

ProtoField_mac::ProtoField_mac(){
  start_value.reset();
  current_value.reset();
} /* End of ProtoField_mac constructor */


ProtoField_mac::ProtoField_mac(MACAddress startvalue){
  this->setStartValue(startvalue);
} /* End of ProtoField_mac constructor */


ProtoField_mac::ProtoField_mac(MACAddress *set, u32 set_len){
  this->setDiscreteSet(set, set_len);
} /* End of ProtoField_mac constructor */


ProtoField_mac::~ProtoField_mac(){

} /* End of ProtoField_mac destructor */


int ProtoField_mac::setStartValue(MACAddress startvalue){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_mac::setDiscreteSet(MACAddress *set, u32 set_len){
  assert(set!=NULL && set_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=set_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_mac::setConstant(MACAddress val){
  this->setStartValue(val);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


/* Note that if the behavior is set to FIELD_TYPE_INCREMENTAL, addresses are
 * always incremented by one. In other words, if something other than 1 was
 * set through a call to setMaxIncrements(), it will be ignored. */
MACAddress ProtoField_mac::getNextValue(){
  MACAddress return_val;
  return_val.reset();
  u8 auxmac[6];
  switch(this->behavior){

    case FIELD_TYPE_CONSTANT:
      return this->start_value;
    break;

    case FIELD_TYPE_INCREMENTAL:
      return_val=this->current_value;
      if(max_increments>0 && increment_count>=max_increments){
        this->current_value=this->start_value;
        this->increment_count=0;
      }else{
        this->current_value.getAddress_bin(auxmac);
        for(int i=5; i>=0; i--){
          if(auxmac[i]<0xFF){
            auxmac[i]=auxmac[i]+1;
            break;
          }else{
            auxmac[i]=0;
          }
        }
        this->current_value.setAddress_bin(auxmac);
        this->increment_count++;
      }
      return return_val;
    break;

    case FIELD_TYPE_RANDOM:
      for(int i=0; i<6; i++)
          auxmac[i]=get_random_u8();
      return_val.setAddress_bin(auxmac);
      return return_val;
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return return_val;
} /* End of getNextValue() */



/*****************************************************************************
 * ProtoField_buff Class                                                       *
 *****************************************************************************/

ProtoField_buff::ProtoField_buff(){
  this->start_value=NULL;
  this->current_value=NULL;
  this->value_len=0;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
} /* End of ProtoField_buff constructor */


ProtoField_buff::ProtoField_buff(u8 *startvalue, u32 value_len){
  this->setStartValue(startvalue, value_len);
} /* End of ProtoField_buff constructor */


ProtoField_buff::ProtoField_buff(u8 **set, u32 each_element_len, u32 number_of_elements){
  this->setDiscreteSet(set, each_element_len, number_of_elements);
} /* End of ProtoField_buff constructor */


ProtoField_buff::~ProtoField_buff(){

} /* End of ProtoField_buff destructor */


int ProtoField_buff::setStartValue(u8 *startvalue, u32 value_len){
  this->start_value=startvalue;
  this->current_value=startvalue;
  this->value_len=value_len;
  this->discrete_set=NULL;
  this->discrete_set_len=0;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setStartValue() */


int ProtoField_buff::setDiscreteSet(u8 **set, u32 each_element_len, u32 number_of_elements){
  assert(set!=NULL && number_of_elements>0 && each_element_len>0);
  this->setBehavior(FIELD_TYPE_DISCRETE_SET);
  this->discrete_set=set;
  this->discrete_set_len=number_of_elements;
  this->value_len=each_element_len;
  this->current_set_element=0;
  this->set=true;
  return OP_SUCCESS;
} /* End of setDiscreteSet() */


/* Sets a constant value for the field. Note that this method overwrites the
 * current field behavior, setting it to FIELD_TYPE_CONSTANT, */
int ProtoField_buff::setConstant(u8 *val, u32 value_len){
  this->setStartValue(val, value_len);
  this->setBehavior(FIELD_TYPE_CONSTANT);
  return OP_SUCCESS;
} /* End of setConstant() */


u8 *ProtoField_buff::getNextValue(){
  return this->getNextValue(NULL);
}


/* @warning If the proto type is FIELD_TYPE_RANDOM the original buffer gets
 * overwritten in every call to getNextValue() */
u8 *ProtoField_buff::getNextValue(u32 *value_len){
  u8 *return_val=NULL;

  if(value_len!=NULL)
    *value_len=this->value_len;

  switch(this->behavior){


    case FIELD_TYPE_CONSTANT:
    case FIELD_TYPE_INCREMENTAL:
      return this->start_value;
    break;

    case FIELD_TYPE_RANDOM:
      /* Overwrite the contents of the original buffer with random data. */
      for(u32 i=0; i<this->value_len; i++){
        this->start_value[i]=get_random_u8();
      }
      return this->start_value;
    break;

    case FIELD_TYPE_DISCRETE_SET:
      assert(this->discrete_set!=NULL);
      return_val = this->discrete_set[this->current_set_element];
      if(this->current_set_element+1>=this->discrete_set_len){
        this->current_set_element=0;
      }else{
        this->current_set_element++;
      }
      return return_val;
    break;
  }
  assert(false);
  return 0;
} /* End of getNextValue() */