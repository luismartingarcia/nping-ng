
/***************************************************************************
 * nse_ssl_cert.cc -- NSE userdatum representing an SSL certificate.       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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

/* $Id:$ */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

extern "C"
{
#include "lua.h"
#include "lauxlib.h"
void *safe_realloc(void *, size_t);
}

#include "nse_nsock.h"

struct cert_userdata {
  X509 *cert;
  int attributes_table;
};

const SSL *nse_nsock_get_ssl(lua_State *L);

/* This is a reference to a table that will be used as the metatable for
   certificate attribute tables. It has an __index entry that points to the
   global table of certificate functions like digest. */
static int ssl_cert_methods_index_ref = LUA_NOREF;

/* Calculate the digest of the certificate using the given algorithm. */
static int ssl_cert_digest(lua_State *L)
{
  struct cert_userdata *udata;
  const char *algorithm;
  unsigned char buf[256];
  size_t n;
  const EVP_MD *md;

  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  algorithm = luaL_checkstring(L, 2);

  md = EVP_get_digestbyname(algorithm);
  if (md == NULL)
      return 0;

  n = sizeof(buf);
  if (X509_digest(udata->cert, md, buf, &n) != 1)
      return 0;
  lua_pushlstring(L, (char *) buf, n);

  return 1;
}

/* These are the contents of the table that is pointed to by the table that has
   ssl_cert_methods_index_ref as a reference. */
static struct luaL_reg ssl_cert_methods[] = {
  { "digest", ssl_cert_digest },
  { NULL, NULL },
};

/* This is a helper function for x509_name_to_table. It takes the ASN1_OBJECT
   passed as an argument, turns it into a table key, and pushes it on the stack.
   The key is a string (like "commonName") if the object has an NID known by
   OBJ_obj2nid; otherwise it is an array containing the OID components as
   strings: { "2", "5", "4", "3" }. */
static void obj_to_key(lua_State *L, const ASN1_OBJECT *obj)
{
  int nid;

  nid = OBJ_obj2nid(obj);
  if (nid == NID_undef) {
    size_t size = 0;
    char *buf = NULL;
    const char *p, *q;
    int i, n;

    while ((n = OBJ_obj2txt(buf, size, obj, 1)) < 0 || (unsigned) n >= size) {
      size = size * 2 + 1;
      buf = (char *) safe_realloc(buf, size);
    }

    lua_newtable(L);

    i = 1;
    p = buf;
    q = p;
    while (*q != '\0') {
      q = strchr(p, '.');
      if (q == NULL)
        q = strchr(p, '\0');
      lua_pushlstring(L, p, q - p);
      lua_rawseti(L, -2, i++);
      p = q + 1;
    }
    free(buf);
  } else {
    lua_pushstring(L, OBJ_nid2ln(nid));
  }
}

/* This is a helper function for l_get_ssl_certificate. It builds a table from
   the given X509_NAME, using keys returned from obj_to_key as keys. The result
   is pushed on the stack. */
static void x509_name_to_table(lua_State *L, X509_NAME *name)
{
  int i;

  lua_newtable(L);

  for (i = 0; i < X509_NAME_entry_count(name); i++) {
    X509_NAME_ENTRY *entry;
    const ASN1_OBJECT *obj;
    const ASN1_STRING *value;

    entry = X509_NAME_get_entry(name, i);
    obj = X509_NAME_ENTRY_get_object(entry);
    value = X509_NAME_ENTRY_get_data(entry);

    obj_to_key(L, obj);
    lua_pushlstring(L, (const char *) value->data, value->length);

    lua_settable(L, -3);
  }
}

/* Parse as a decimal integer the len characters starting at s. This function
   can only process positive numbers; if the return value is negative then a
   parsing error occurred. */
static int parse_int(const unsigned char *s, size_t len)
{
  char buf[32];
  char *tail;
  long v;

  if (len == 0)
    return -1;
  if (!isdigit((int) (unsigned char) s[0]))
    return -1;
  if (len > sizeof(buf) - 1)
    return -1;
  memcpy(buf, s, len);
  buf[len] = '\0';

  errno = 0;
  v = strtol(buf, &tail, 10);
  if (errno != 0 || *tail != '\0')
    return -1;
  if ((int) v != v || v < 0)
    return -1;

  return (int) v;
}

/* This is a helper function for asn1_time_to_obj. It parses a tectual ASN1_TIME
   value and stores the time in the given struct tm. It returns 0 on success and
   -1 on a parse error. */
static int time_to_tm(const ASN1_TIME *t, struct tm *result)
{
  const unsigned char *p;

  p = t->data;
  if (t->length == 13 && t->data[t->length - 1] == 'Z') {
    /* yymmddhhmmssZ */
    int year;

    year = parse_int(t->data, 2);
    if (year < 0)
      return -1;
    /* "In coming up with the worlds least efficient machine-readable time
       encoding format, the ISO nevertheless decided to forgo the encoding of
       centuries, a problem which has been kludged around by redefining the time
       as UTCTime if the date is 2049 or ealier, and GeneralizedTime if the date
       is 2050 or later."
       http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt */
    if (year < 50)
      result->tm_year = 2000 + year;
    else
      result->tm_year = 1900 + year;
    p = t->data + 2;
  } else if (t->length == 14) {
    /* yyyymmddhhmmss */
    result->tm_year = parse_int(t->data, 4);
    if (result->tm_year < 0)
      return -1;
    p = t->data + 4;
  } else {
    return -1;
  }

  result->tm_mon = parse_int(p, 2);
  result->tm_mday = parse_int(p + 2, 2);
  result->tm_hour = parse_int(p + 4, 2);
  result->tm_min = parse_int(p + 6, 2);
  result->tm_sec = parse_int(p + 8, 2);

  if (result->tm_mon < 0 || result->tm_mday < 0 || result->tm_hour < 0
      || result->tm_min < 0 || result->tm_sec < 0) {
    return -1;
  }

  return 0;
}

/* This is a helper function for asn1_time_to_obj. It converts a struct tm into
   a date table as returned by the Lua date os.date("!*t"), with the exception
   that the wday and yday fields are not present. */
static void tm_to_table(lua_State *L, const struct tm *tm)
{
  lua_newtable(L);

  lua_pushnumber(L, tm->tm_year);
  lua_setfield(L, -2, "year");
  lua_pushnumber(L, tm->tm_mon + 1);
  lua_setfield(L, -2, "month");
  lua_pushnumber(L, tm->tm_mday);
  lua_setfield(L, -2, "day");
  lua_pushnumber(L, tm->tm_hour);
  lua_setfield(L, -2, "hour");
  lua_pushnumber(L, tm->tm_min);
  lua_setfield(L, -2, "min");
  lua_pushnumber(L, tm->tm_sec);
  lua_setfield(L, -2, "sec");
  /* Omit tm_wday and tm_yday. */
}

/* This is a helper functino for x509_validity_to_table. It takes teh given
   ASN1_TIME and covnerts it to a value on the stack, which is one of
     nil, if the time is NULL;
     a date table, if the date can be parsed; and
     a string of the raw bytes, if the date cannot be parsed. */
static void asn1_time_to_obj(lua_State *L, const ASN1_TIME *s)
{
  struct tm tm;

  if (s == NULL) {
      lua_pushnil(L);
  } else if (time_to_tm(s, &tm) == 0) {
      tm_to_table(L, &tm);
  } else {
      lua_pushlstring(L, (const char *) s->data, s->length);
  }
}

/* This is a helper functino for x509_validity_to_table. It builds a table with
   the two members "notBefore" and "notAfter", whose values are what is returned
   from asn1_time_to_obj. */
static void x509_validity_to_table(lua_State *L, const X509 *cert)
{
  lua_newtable(L);

  asn1_time_to_obj(L, X509_get_notBefore(cert));
  lua_setfield(L, -2, "notBefore");
  asn1_time_to_obj(L, X509_get_notAfter(cert));
  lua_setfield(L, -2, "notAfter");
}

/* This is a helper function for l_get_ssl_certificate. It converts the
   certificate into a PEM-encoded string on the stack. */
static void cert_pem_to_string(lua_State *L, X509 *cert)
{
  BIO *bio;
  char *buf;
  long size;

  bio = BIO_new(BIO_s_mem());
  assert(bio != NULL);

  assert(PEM_write_bio_X509(bio, cert));

  size = BIO_get_mem_data(bio, &buf);
  lua_pushlstring(L, buf, size);

  BIO_vfree(bio);
}

int l_get_ssl_certificate(lua_State *L)
{
  const SSL *ssl;
  struct cert_userdata *udata;
  X509 *cert;
  X509_NAME *subject, *issuer;

  ssl = nse_nsock_get_ssl(L);
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    lua_pushnil(L);
    return 1;
  }

  udata = (struct cert_userdata *) lua_newuserdata(L, sizeof(*udata));
  udata->cert = cert;

  lua_newtable(L);

  subject = X509_get_subject_name(cert);
  if (subject != NULL) {
    x509_name_to_table(L, subject);
    lua_setfield(L, -2, "subject");
  }

  issuer = X509_get_issuer_name(cert);
  if (issuer != NULL) {
    x509_name_to_table(L, issuer);
    lua_setfield(L, -2, "issuer");
  }

  x509_validity_to_table(L, cert);
  lua_setfield(L, -2, "validity");

  cert_pem_to_string(L, cert);
  lua_setfield(L, -2, "pem");

  /* At this point the certificate-specific table of attributes is at the top of
     the stack. We give it a metatable with an __index entry that points into
     the global shared table of certificate functions. */
  lua_rawgeti(L, LUA_REGISTRYINDEX, ssl_cert_methods_index_ref);
  lua_setmetatable(L, -2);

  udata->attributes_table = luaL_ref(L, LUA_REGISTRYINDEX);

  luaL_getmetatable(L, "SSL_CERT");
  lua_setmetatable(L, -2);

  return 1;
}

static int l_ssl_cert_index(lua_State *L)
{
  struct cert_userdata *udata;
  
  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  lua_rawgeti(L, LUA_REGISTRYINDEX, udata->attributes_table);
  /* The key. */
  lua_pushvalue(L, 2);
  /* Look it up in the table of attributes. */
  lua_gettable(L, -2);

  return 1;
}

static int l_ssl_cert_gc(lua_State *L)
{
  struct cert_userdata *udata;
  
  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  X509_free(udata->cert);
  luaL_unref(L, LUA_REGISTRYINDEX, udata->attributes_table);

  return 0;
}

void nse_nsock_init_ssl_cert(lua_State *L)
{
  luaL_newmetatable(L, "SSL_CERT");
  lua_pushcclosure(L, l_ssl_cert_index, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcclosure(L, l_ssl_cert_gc, 0);
  lua_setfield(L, -2, "__gc");

  /* Create a table with an __index entry that will be used as a metatable for
     per-certificate attribute tables. This gives the tables access to the
     global shared table of certificate functions. */
  lua_newtable(L);
  lua_newtable(L);
  luaL_register(L, NULL, ssl_cert_methods);
  lua_setfield(L, -2, "__index");
  ssl_cert_methods_index_ref = luaL_ref(L, LUA_REGISTRYINDEX);
}
