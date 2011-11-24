
/***************************************************************************
 * ProtoField.h --                                                         *
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

#ifndef __PROTOFIELD_H__
#define __PROTOFIELD_H__ 1

#include "nping.h"

#define FIELD_TYPE_CONSTANT     0
#define FIELD_TYPE_INCREMENTAL  1
#define FIELD_TYPE_RANDOM       2
#define FIELD_TYPE_DISCRETE_SET 3


/*****************************************************************************
 * ProtoField Class                                                          *
 *****************************************************************************/

class ProtoField{
  protected:
    int behavior;
    u32 increment_value;
    u32 max_increments;
    u32 increment_count;
    bool set;

  public:
    ProtoField();
    ~ProtoField();
    int setBehavior(int val);
    int getBehavior();
    int setIncrementValue(u32 val);
    int setMaxIncrements(u32 val);
    bool is_set();
};


/*****************************************************************************
 * ProtoField_u8 Class                                                       *
 *****************************************************************************/

class ProtoField_u8 : public ProtoField{
  private:
    u8 start_value;
    u8 current_value;
    u8 *discrete_set;
    u32 discrete_set_len;
    u32 current_set_element;

  public:
    ProtoField_u8();
    ProtoField_u8(u8 startvalue);
    ProtoField_u8(u8 *set, u32 set_len);
    ~ProtoField_u8();
    u8 getNextValue();
    int setDiscreteSet(u8 *set, u32 set_len);
    int setStartValue(u8 startvalue);
    int setConstant(u8 val);

};


/*****************************************************************************
 * ProtoField_u16 Class                                                       *
 *****************************************************************************/

class ProtoField_u16 : public ProtoField{
  private:
    u16 start_value;
    u16 current_value;
    u16 *discrete_set;
    u32 discrete_set_len;
    u32 current_set_element;

  public:
    ProtoField_u16();
    ProtoField_u16(u16 startvalue);
    ProtoField_u16(u16 *set, u32 set_len);
    ~ProtoField_u16();
    u16 getNextValue();
    int setDiscreteSet(u16 *set, u32 set_len);
    int setStartValue(u16 startvalue);
    int setConstant(u16 val);

};

/*****************************************************************************
 * ProtoField_u32 Class                                                       *
 *****************************************************************************/

class ProtoField_u32 : public ProtoField{
  private:
    u32 start_value;
    u32 current_value;
    u32 *discrete_set;
    u32 discrete_set_len;
    u32 current_set_element;

  public:
    ProtoField_u32();
    ProtoField_u32(u32 startvalue);
    ProtoField_u32(u32 *set, u32 set_len);
    ~ProtoField_u32();
    u32 getNextValue();
    int setDiscreteSet(u32 *set, u32 set_len);
    int setStartValue(u32 startvalue);
    int setConstant(u32 val);

};

/*****************************************************************************
 * ProtoField_bool Class                                                       *
 *****************************************************************************/

class ProtoField_bool : public ProtoField{
  private:
    bool start_value;
    bool current_value;
    bool *discrete_set;
    u32 discrete_set_len;
    u32 current_set_element;

  public:
    ProtoField_bool();
    ProtoField_bool(bool startvalue);
    ProtoField_bool(bool *set, u32 set_len);
    ~ProtoField_bool();
    bool getNextValue();
    int setDiscreteSet(bool *set, u32 set_len);
    int setStartValue(bool startvalue);
    int setConstant(bool val);

};


/*****************************************************************************
 * ProtoField_inaddr Class                                                   *
 *****************************************************************************/

class ProtoField_inaddr : public ProtoField{
  private:
    struct in_addr start_value;
    struct in_addr current_value;
    struct in_addr  *discrete_set;
    u32 discrete_set_len;
    u32 current_set_element;

  public:
    ProtoField_inaddr();
    ProtoField_inaddr(struct in_addr startvalue);
    ProtoField_inaddr(struct in_addr *set, u32 set_len);
    ~ProtoField_inaddr();
    struct in_addr getNextValue();
    int setDiscreteSet(struct in_addr *set, u32 set_len);
    int setStartValue(struct in_addr startvalue);
    int setConstant(struct in_addr val);

};



#endif /* __PROTOFIELD_H__ */
