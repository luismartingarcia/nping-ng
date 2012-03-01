 
/***************************************************************************
 * NEPContext.cc --                                                        *
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

#include "nping.h"
#include "NEPContext.h"
#include "Crypto.h"
#include "EchoHeader.h"
#include "nbase.h"
#include "NpingOps.h"

extern NpingOps o;

NEPContext::NEPContext() {
  this->reset();
} /* End of NEPContext constructor */


NEPContext::~NEPContext() {
} /* End of NEPContext destructor */


/** Sets every attribute to its default value- */
void NEPContext::reset() {
  this->id=CLIENT_NOT_FOUND;
  this->nsi=NULL;
  this->state=STATE_LISTEN;
  this->last_seq_client=0;
  this->last_seq_server=0;
  memset(this->next_iv_enc, 0, CIPHER_BLOCK_SIZE);
  memset(this->next_iv_dec, 0, CIPHER_BLOCK_SIZE);
  memset(this->nep_key_mac_c2s, 0, MAC_KEY_LEN);
  memset(this->nep_key_mac_s2c, 0, MAC_KEY_LEN);
  memset(this->nep_key_ciphertext_c2s, 0, CIPHER_KEY_LEN);
  memset(this->nep_key_ciphertext_s2c, 0, CIPHER_KEY_LEN);
  memset(this->server_nonce, 0, NONCE_LEN);
  memset(this->client_nonce, 0, NONCE_LEN);
  memset(&this->clnt_addr, 0, sizeof(struct sockaddr_storage ));
  server_nonce_set=false;
  client_nonce_set=false;
} /* End of reset() */


clientid_t NEPContext::getIdentifier(){
  return this->id;
} /* End of getIdentifier() */


int NEPContext::setIdentifier(clientid_t clnt){
  this->id=clnt;
  return OP_SUCCESS;
} /* End of setIdentifier() */


struct sockaddr_storage NEPContext::getAddress(){
  return this->clnt_addr;
} /* End of getAddress() */


int NEPContext::setAddress(struct sockaddr_storage a){
  this->clnt_addr=a;
  return OP_SUCCESS;
} /* End of setAddress() */

nsock_iod NEPContext::getNsockIOD(){
  return this->nsi;
} /* End of getNsockIOD() */


int NEPContext::setNsockIOD(nsock_iod iod){
  this->nsi=iod;
  return OP_SUCCESS;
} /* End of setNsockIOD() */


bool NEPContext::ready(){
  return (this->state==STATE_READY_SENT);
}

int NEPContext::setState(int st){
  this->state=st;
  return OP_SUCCESS;
} /* End of setState() */


int NEPContext::getState(){
  return this->state;
} /* End of getState() */


int NEPContext::setNextEncryptionIV(u8 *block){
  if(block==NULL)
    return OP_FAILURE;
  else{
    memcpy(this->next_iv_enc, block, CIPHER_BLOCK_SIZE);
    return OP_SUCCESS;
  }
} /* End of setLastBlock4Encryption() */


u8 *NEPContext::getNextEncryptionIV(size_t *final_len){
  if(final_len!=NULL)
    *final_len=CIPHER_BLOCK_SIZE;
  return this->next_iv_enc;
} /* End of getLastBlock4Encryption() */


u8 *NEPContext::getNextEncryptionIV(){
  return this->getNextEncryptionIV(NULL);
} /* End of getLastBlock4Encryption() */


int NEPContext::setNextDecryptionIV(u8 *block){
  if(block==NULL)
    return OP_FAILURE;
  else{
    memcpy(this->next_iv_dec, block, CIPHER_BLOCK_SIZE);
    return OP_SUCCESS;
  }
} /* End of setLastBlock4Decryption() */


u8 *NEPContext::getNextDecryptionIV(size_t *final_len){
  if(final_len!=NULL)
    *final_len=CIPHER_BLOCK_SIZE;
  return this->next_iv_dec;
} /* End of getLastBlock4Decryption() */


u8 *NEPContext::getNextDecryptionIV(){
  return this->getNextDecryptionIV(NULL);
} /* End of getLastBlock4Decryption() */


int NEPContext::setLastServerSequence(u32 seq){
  this->last_seq_server=seq;
  return OP_SUCCESS;
} /* End of setLastServerSequence() */


u32 NEPContext::getLastServerSequence(){
  return this->last_seq_server;
} /* End of getLastServerSequence() */


/** Increments current server sequence number by one and returns it.
  * @warning this function changes object's internal state. It should be
  * called only when the caller wants to increment the internal last_seq_client
  * attribute. */
u32 NEPContext::getNextServerSequence(){
  if( this->last_seq_server==0xFFFFFFFF)
    this->last_seq_server=0; /* Wrap back to zero */
  else
    this->last_seq_server++;
  return this->last_seq_server;
} /* End of getNextServerSequence() */


int NEPContext::setLastClientSequence(u32 seq){
  this->last_seq_client=seq;
  return OP_SUCCESS;
} /* End of setLastClientSequence() */


u32 NEPContext::getLastClientSequence(){
  return this->last_seq_client;
} /* End of getLastClientSequence() */


/** Increments current client sequence number by one and returns it.
  * @warning this function changes object's internal state. It should be
  * called only when the caller wants to increment the internal last_seq_client
  * attribute. */
u32 NEPContext::getNextClientSequence(){
  if( this->last_seq_client==0xFFFFFFFF)
    this->last_seq_client=0; /* Wrap back to zero */
  else
    this->last_seq_client++;
  return this->last_seq_client;
} /* End of getNextClientSequence() */


int NEPContext::generateInitialServerSequence(){
  return Crypto::generateNonce((u8 *)&(this->last_seq_server), sizeof(u32));
} /* End of generateInitialServerSequence() */


int NEPContext::generateInitialClientSequence(){
  return Crypto::generateNonce((u8 *)&(this->last_seq_client), sizeof(u32));
} /* End of generateInitialClientSequence() */


u8 *NEPContext::generateKey(int key_type, size_t *final_len){
  u8 data[1024];
  char key_type_id[128+1];
  size_t len=0;

  /* Copy the passphrase */
  char *passphrase=o.getEchoPassphrase();
  size_t plen=strlen(passphrase);
  memcpy(data, passphrase, plen);
  len+=plen;

  /* Copy the nonces */
  memcpy(data+len, this->getServerNonce(), NONCE_LEN );
  len+=NONCE_LEN;
  if(key_type==MAC_KEY_S2C_INITIAL){
    memset(data+len, 0, NONCE_LEN); /* Empty nonce in this case */
    len+=NONCE_LEN;
  }else{
    memcpy(data+len, this->getClientNonce(), NONCE_LEN);
    len+=NONCE_LEN;
  }

  switch(key_type){

    case MAC_KEY_S2C_INITIAL:
        strncpy(key_type_id, "NEPkeyforMACServer2ClientInitial", 128);
    break;
    case MAC_KEY_S2C:
        strncpy(key_type_id, "NEPkeyforMACServer2Client", 128);
    break;
    case MAC_KEY_C2S:
        strncpy(key_type_id, "NEPkeyforMACClient2Server", 128);
    break;
    case CIPHER_KEY_C2S:
        strncpy(key_type_id, "NEPkeyforCiphertextClient2Server", 128);
    break;
    case CIPHER_KEY_S2C:
        strncpy(key_type_id, "NEPkeyforCiphertextServer2Client", 128);
    break;
    default:
        return NULL;
    break;
  }

  /* Copy the id */
  memcpy(data+len, key_type_id, strlen(key_type_id));
  len+=strlen(key_type_id);

  return Crypto::deriveKey(data, len, final_len);
} /* End of generateKey() */


/** Set key for C->S MAC computation (NEP_KEY_MAC_C2S)*/
int NEPContext::setMacKeyC2S(u8 *key){
  if(key==NULL)
    return OP_FAILURE;
  else
    memcpy(this->nep_key_mac_c2s, key, MAC_KEY_LEN);
  return OP_SUCCESS;
} /* End of setMacKeyC2S() */


/** Returns NEP_KEY_MAC_C2S key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getMacKeyC2S(size_t *final_len){
  if(final_len!=NULL)
    *final_len=MAC_KEY_LEN;
  return this->nep_key_mac_c2s;     
} /* End of getMacKeyC2S() */


/** Returns NEP_KEY_MAC_C2S key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getMacKeyC2S(){
  return this->getMacKeyC2S(NULL);
} /* End of getMacKeyC2S() */


int NEPContext::generateMacKeyC2S(){
  u8 *key=NULL;
  size_t len=0;
  if( (key=this->generateKey(MAC_KEY_C2S, &len))==NULL )
    return OP_FAILURE;
  return this->setMacKeyC2S(key);
} /* End of generateMacKeyC2S() */


/** Set key for S->C MAC computation (NEP_KEY_MAC_S2C) */
int NEPContext::setMacKeyS2C(u8 *key){
  if(key==NULL)
    return OP_FAILURE;
  else
    memcpy(this->nep_key_mac_s2c, key, MAC_KEY_LEN);
  return OP_SUCCESS;
} /* End of setMacKeyS2C() */


/** Returns NEP_KEY_MAC_S2C key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getMacKeyS2C(size_t *final_len){
  if(final_len!=NULL)
    *final_len=MAC_KEY_LEN;
  return this->nep_key_mac_s2c;     
} /* End of getMacKeyS2C() */



/** Returns NEP_KEY_MAC_S2C key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getMacKeyS2C(){
  return this->getMacKeyS2C(NULL);
} /* End of getMacKeyS2C() */


int NEPContext::generateMacKeyS2C(){
  u8 *key=NULL;
  size_t len=0;
  if( (key=this->generateKey(MAC_KEY_S2C, &len))==NULL )
    return OP_FAILURE;
  return this->setMacKeyS2C(key);
} /* End of generateMacKeyS2C() */


int NEPContext::generateMacKeyS2CInitial(){
  u8 *key=NULL;
  size_t len=0;
  if( (key=this->generateKey(MAC_KEY_S2C_INITIAL, &len))==NULL )
    return OP_FAILURE;
  return this->setMacKeyS2C(key);
} /* End of generateMacKeyS2CInitial() */


/** Set cipher key for C->S ciphertext (NEP_KEY_CIPHERTEXT_C2S) */
int NEPContext::setCipherKeyC2S(u8 *key){
  if(key==NULL)
    return OP_FAILURE;
  else
    memcpy(this->nep_key_ciphertext_c2s, key, CIPHER_KEY_LEN);
  return OP_SUCCESS;
} /* End of setCipherKeyC2S() */


/** Returns NEP_KEY_CIPHERTEXT_C2S key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getCipherKeyC2S(size_t *final_len){
  if(final_len!=NULL)
    *final_len=MAC_KEY_LEN;
  return this->nep_key_ciphertext_c2s;
} /* End of getCipherKeyC2S() */


/** Returns NEP_KEY_CIPHERTEXT_C2S key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getCipherKeyC2S(){
  return this->getCipherKeyC2S(NULL);
} /* End of getCipherKeyC2S() */


int NEPContext::generateCipherKeyC2S(){
  u8 *key=NULL;
  size_t len=0;
  if( (key=this->generateKey(CIPHER_KEY_C2S, &len))==NULL )
    return OP_FAILURE;
  return this->setCipherKeyC2S(key);
} /* End of generateCipherKeyC2S() */


/** Set cipher key for S->C ciphertext (NEP_KEY_CIPHERTEXT_S2C) */
int NEPContext::setCipherKeyS2C(u8 *key){
  if(key==NULL)
    return OP_FAILURE;
  else
    memcpy(this->nep_key_ciphertext_s2c, key, CIPHER_KEY_LEN);
  return OP_SUCCESS;
} /* End of setCipherKeyS2C() */


/** Returns NEP_KEY_CIPHERTEXT_S2C key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getCipherKeyS2C(size_t *final_len){
  if(final_len!=NULL)
    *final_len=CIPHER_KEY_LEN;
  return this->nep_key_ciphertext_s2c;     
} /* End of getCipherKeyS2C() */


/** Returns NEP_KEY_CIPHERTEXT_S2C key. If final_len is not NULL, key length
  * is stored in it. */
u8 *NEPContext::getCipherKeyS2C(){
  return this->getCipherKeyS2C(NULL);
} /* End of getCipherKeyS2C() */


int NEPContext::generateCipherKeyS2C(){
  u8 *key=NULL;
  size_t len=0;
  if( (key=this->generateKey(CIPHER_KEY_S2C, &len))==NULL )
    return OP_FAILURE;
  return this->setCipherKeyS2C(key);
} /* End of generateCipherKeyS2C() */


/** Generates a random nonce which is, if possible, cryptographically secure.
  * This method is used by the Echo client to generate its own nonce for the
  * initial NEP_HANDSHAKE_CLIENT message */
int NEPContext::generateClientNonce(){
    return Crypto::generateNonce(this->client_nonce, NONCE_LEN);
} /* End of generateClientNonce() */


/** Generates a random nonce which is, if possible, cryptographically secure.
  * This method is used by the Echo server to generate its own nonce for the
  * initial NEP_HANDSHAKE_SERVER message */
int NEPContext::generateServerNonce(){
    return Crypto::generateNonce(this->server_nonce, NONCE_LEN);
} /* End of generateServerNonce() */


/** This method is used by the Echo server to store the initial nonce received
  * from the client. */
int NEPContext::setClientNonce(u8 *buff){
  if(buff==NULL)
    return OP_FAILURE;
  else{
    memcpy(this->client_nonce, buff, NONCE_LEN);
    this->client_nonce_set=true;
  }
  return OP_SUCCESS;
} /* End of setClientNonce() */


/** This method is used by the Echo client to store the initial nonce received
  * from the server. */
int NEPContext::setServerNonce(u8 *buff){
  if(buff==NULL)
    return OP_FAILURE;
  else{
    memcpy(this->server_nonce, buff, NONCE_LEN);
    this->server_nonce_set=true;
  }
  return OP_SUCCESS;
} /* End of setServerNonce() */


u8 *NEPContext::getClientNonce(){
  return this->client_nonce;
} /* End of getClientNonce() */


u8 *NEPContext::getServerNonce(){
  return this->server_nonce;
} /* End of getServerNonce() */


/** Adds a field specifier, received from the client in a NEP_PACKET_SPEC
  * message. */
int NEPContext::addClientFieldSpec(u8 field, u8 len, u8 *value){
  fspec_t t;
  if(value==NULL){
    return OP_FAILURE;
  }else{
    t.field=field;
    t.len=MIN(len, PACKETSPEC_FIELD_LEN);
    memcpy(t.value, value, t.len);
    this->fspecs.push_back(t);
  }
  return OP_SUCCESS;
} /* End of addClientFieldSpec() */


/** Returns a pointer to the N-th client's field specifier. Callers should start
  * passing 0 and then incrementing the index by one until it returns NULL */
fspec_t *NEPContext::getClientFieldSpec(int index){
  if(index<0 || index>=(int)this->fspecs.size() )
    return NULL;
  else
    return &(this->fspecs[index]);
} /* End of getClientFieldSpec() */


/** Returns true if we already have a packet spec of the same type. This
  * method should be called for EVERY spec in a NEP_PACKET_SPEC message, to
  * ensure that malicious clients are not supplying the same spec repeatedly
  * to increase their packet score. */
bool NEPContext::isDuplicateFieldSpec(u8 test_field){
 int i=0;
 fspec_t *spec=NULL;

 /* Iterate through the list of stored specs and determine if we already
    have a spec of the same type. */
 while( (spec=this->getClientFieldSpec(i++))!=NULL ){
     if(spec->field==test_field)
         return true;
 }
 return false;
} /* End of isDuplicateFieldSpect() */


/** Deletes all previous field specifiers. This should be used when dealing
  * with clients that send multiple NEP_PACKET_SPEC messages, so only the last
  * PacketSpec is taken into account. */
int NEPContext::resetClientFieldSpecs(){
  this->fspecs.empty();
  return OP_SUCCESS;
} /* End of resetClientFieldSpecs() */