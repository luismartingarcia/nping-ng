
/***************************************************************************
 * osscan.cc -- Routines used for OS detection via TCP/IP fingerprinting.  *
 * For more information on how this works in Nmap, see my paper at         *
 * http://nmap.org/osdetect/                                               *
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

/* $Id$ */

#include "osscan.h"
#include "timing.h"
#include "NmapOps.h"
#include "nmap_tty.h"
#include "charpool.h"
#include "Target.h"
#include "nmap_error.h"
#include "utils.h"

#include <stdarg.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <list>
#include <set>

extern NmapOps o;

/* Store a string uniquely. The first time this function is called with a
   certain string, it allocates memory and stores a copy of the string in a
   static pool. Thereafter it will return a pointer to the saved string instead
   of allocating memory for an identical one. */
const char *string_pool_insert(const char *s)
{
  static std::set<std::string> pool;
  static std::pair<std::set<std::string>::iterator, bool> pair;

  pair = pool.insert(s);

  return pair.first->c_str();
}

const char *string_pool_substr(const char *s, const char *t)
{
  return string_pool_insert(std::string(s, t).c_str());
}

const char *string_pool_substr_strip(const char *s, const char *t) {
  while (isspace((int) (unsigned char) *s))
    s++;
  while (t > s && isspace((int) (unsigned char) *(t - 1)))
    t--;

  return string_pool_substr(s, t);
}

/* Skip over whitespace to find the beginning of a word, then read until the
   next whilespace character. Returns NULL if only whitespace is found. */
static const char *string_pool_strip_word(const char *s) {
  const char *t;

  while (isspace((int) (unsigned char) *s))
    s++;
  t = s;
  while (*t != '\0' && !isspace((int) (unsigned char) *t))
    t++;

  if (s == t)
    return NULL;

  return string_pool_substr(s, t);
}

/* Format a string with sprintf and insert it with string_pool_insert. */
const char *string_pool_sprintf(const char *fmt, ...)
{
  const char *s;
  char *buf;
  int size, n;
  va_list ap;

  buf = NULL;
  size = 32;
  /* Loop until we allocate a string big enough for the sprintf. */
  for (;;) {
    buf = (char *) realloc(buf, size);
    assert(buf != NULL);
    va_start(ap, fmt);
    n = Vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    if (n < 0)
      size = size * 2;
    else if (n >= size)
      size = n + 1;
    else
      break;
  }

  s = string_pool_insert(buf);
  free(buf);

  return s;
}

FingerPrintDB::FingerPrintDB() : MatchPoints(NULL) {
}

FingerPrintDB::~FingerPrintDB() {
  std::vector<FingerPrint *>::iterator current;

  if (MatchPoints != NULL)
    delete MatchPoints;
  for (current = prints.begin(); current != prints.end(); current++)
    delete *current;
}

FingerPrint::FingerPrint() {
}

const struct AVal *FingerTest::getattrbyname(const char *name) const {
  std::vector<struct AVal>::const_iterator i;

  for (i = results.begin(); i != results.end(); i++) {
    if (strcmp(i->attribute, name) == 0)
      return &*i;
  }

  return NULL;
}

const FingerTest *FingerPrint::gettestbyname(const char *name) const {
  std::vector<FingerTest>::const_iterator i;

  for (i = tests.begin(); i != tests.end(); i++) {
    if (strcmp(i->name, name) == 0)
      return &*i;
  };

  return NULL;
}

/* Returns true if perfect match -- if num_subtests &
   num_subtests_succeeded are non_null it ADDS THE NEW VALUES to what
   is already there.  So initialize them to zero first if you only
   want to see the results from this match.  if shortcircuit is zero,
   it does all the tests, otherwise it returns when the first one
   fails.  If you want details of the match process printed, pass n
   onzero for 'verbose'.  If points is non-null, it is examined to
   find the number of points for each test in the fprint AVal and use
   that the increment num_subtests and num_subtests_succeeded
   appropriately.  If it is NULL, each test is worth 1 point.  In that
   case, you may also pass in the group name (SEQ, T1, etc) to have
   that extra info printed.  If you pass 0 for verbose, you might as
   well pass NULL for testGroupName as it won't be used. */
static int AVal_match(const FingerTest *reference, const FingerTest *fprint, const FingerTest *points,
                      unsigned long *num_subtests,
                      unsigned long *num_subtests_succeeded, int shortcut,
                      int verbose, const char *testGroupName) {
  std::vector<struct AVal>::const_iterator current_ref;
  const struct AVal *current_fp;
  const struct AVal *current_points;
  unsigned int number, number1;
  unsigned int val;
  char *p, *q, *q1;  /* OHHHH YEEEAAAAAHHHH!#!@#$!% */
  char valcpy[512];
  char *endptr;
  int andexp, orexp, expchar, numtrue;
  int testfailed;
  int subtests = 0, subtests_succeeded=0;
  int pointsThisTest = 1;

  for (current_ref = reference->results.begin();
       current_ref != reference->results.end();
       current_ref++) {
    current_fp = fprint->getattrbyname(current_ref->attribute);
    if (!current_fp)
      continue;
    /* OK, we compare an attribute value in  current_fp->value to a
       potentially large expression in current_ref->value.  The syntax
       uses < (less than), > (greather than), + (non-zero), | (or), -
       (range), and & (and).  No parenthesis are allowed */
    numtrue = andexp = orexp = 0; testfailed = 0;
    Strncpy(valcpy, current_ref->value, sizeof(valcpy));
    p = valcpy;

    if (strchr(current_ref->value, '|')) {
      orexp = 1; expchar = '|';
    } else {
      andexp = 1; expchar = '&';
    }

    do {
      q = strchr(p, expchar);
      if (q)
        *q = '\0';
      if (strcmp(p, "+") == 0) {
        if (!*current_fp->value) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        } else {
          val = strtol(current_fp->value, &endptr, 16);
          if (val == 0 || *endptr) {
            if (andexp) {
              testfailed = 1;
              break;
            }
          } else {
            numtrue++;
            if (orexp)
              break;
          }
        }
      } else if (*p == '<' && isxdigit((int) (unsigned char) p[1])) {
        if (!*current_fp->value) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        }
        number = strtol(p + 1, &endptr, 16);
        val = strtol(current_fp->value, &endptr, 16);
        if (val >= number || *endptr) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        } else {
          numtrue++;
          if (orexp)
            break;
        }
      } else if (*p == '>' && isxdigit((int) (unsigned char) p[1])) {
        if (!*current_fp->value) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        }
        number = strtol(p + 1, &endptr, 16);
        val = strtol(current_fp->value, &endptr, 16);
        if (val <= number || *endptr) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        } else {
          numtrue++;
          if (orexp)
            break;
        }
      } else if (((q1 = strchr(p, '-')) != NULL) && isxdigit((int) (unsigned char) p[0]) && isxdigit((int) (unsigned char) q1[1])) {
        if (!*current_fp->value) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        }
        *q1 = '\0';
        number = strtol(p, NULL, 16);
        number1 = strtol(q1 + 1, NULL, 16);
        if (number1 < number && o.debugging) {
          error("Range error in reference aval: %s=%s", current_ref->attribute, current_ref->value);
        }
        val = strtol(current_fp->value, &endptr, 16);
        if (val < number || val > number1 || *endptr) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        } else {
          numtrue++;
          if (orexp)
            break;
        }
      } else {
        if (strcmp(p, current_fp->value)) {
          if (andexp) {
            testfailed = 1;
            break;
          }
        } else {
          numtrue++;
          if (orexp)
            break;
        }
      }
      if (q)
        p = q + 1;
    } while (q);

    if (numtrue == 0)
      testfailed = 1;
    if (points) {
      current_points = points->getattrbyname(current_ref->attribute);
      if (!current_points)
        fatal("%s: Failed to find point amount for test %s.%s", __func__, testGroupName? testGroupName : "", current_ref->attribute);
      errno = 0;
      pointsThisTest = strtol(current_points->value, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || pointsThisTest < 0)
        fatal("%s: Got bogus point amount (%s) for test %s.%s", __func__, current_points->value, testGroupName? testGroupName : "", current_ref->attribute);
    }
    subtests += pointsThisTest;
    if (testfailed) {
      if (shortcut) {
        if (num_subtests)
          *num_subtests += subtests;
        return 0;
      }
      if (verbose)
        log_write(LOG_PLAIN, "%s.%s: \"%s\" NOMATCH \"%s\" (%d %s)\n", testGroupName,
                  current_ref->attribute, current_fp->value,
                  current_ref->value, pointsThisTest, (pointsThisTest == 1) ? "point" : "points");
    } else {
      subtests_succeeded += pointsThisTest;
    }
    /* Whew, we made it past one Attribute alive , on to the next! */
  }
  if (num_subtests)
    *num_subtests += subtests;
  if (num_subtests_succeeded)
    *num_subtests_succeeded += subtests_succeeded;

  return (subtests == subtests_succeeded) ? 1 : 0;
}

/* Compares 2 fingerprints -- a referenceFP (can have expression
   attributes) with an observed fingerprint (no expressions).  If
   verbose is nonzero, differences will be printed.  The comparison
   accuracy (between 0 and 1) is returned).  If MatchPoints is not NULL, it is
   a special "fingerprints" which tells how many points each test is worth. */
double compare_fingerprints(FingerPrint *referenceFP, FingerPrint *observedFP,
                            FingerPrint *MatchPoints, int verbose) {
  std::vector<FingerTest>::iterator currentReferenceTest;
  const FingerTest *currentObservedTest;
  const FingerTest *currentTestMatchPoints;
  unsigned long num_subtests = 0, num_subtests_succeeded = 0;
  unsigned long  new_subtests, new_subtests_succeeded;
  assert(referenceFP);
  assert(observedFP);

  for (currentReferenceTest = referenceFP->tests.begin();
       currentReferenceTest != referenceFP->tests.end();
       currentReferenceTest++) {
    currentObservedTest = observedFP->gettestbyname(currentReferenceTest->name);
    if (currentObservedTest) {
      new_subtests = new_subtests_succeeded = 0;
      if (MatchPoints) {
        currentTestMatchPoints = MatchPoints->gettestbyname(currentReferenceTest->name);
        if (!currentTestMatchPoints)
          fatal("%s: Failed to locate test %s in MatchPoints directive of fingerprint file", __func__, currentReferenceTest->name);
      } else {
        currentTestMatchPoints = NULL;
      }

      AVal_match(&*currentReferenceTest, currentObservedTest, currentTestMatchPoints,
                 &new_subtests, &new_subtests_succeeded, 0, verbose, currentReferenceTest->name);
      num_subtests += new_subtests;
      num_subtests_succeeded += new_subtests_succeeded;
    }
  }

  assert(num_subtests_succeeded <= num_subtests);
  return (num_subtests) ? (num_subtests_succeeded / (double) num_subtests) : 0;
}

/* Takes a fingerprint and looks for matches inside the passed in
   reference fingerprint DB.  The results are stored in in FPR (which
   must point to an instantiated FingerPrintResultsIPv4 class) -- results
   will be reverse-sorted by accuracy.  No results below
   accuracy_threshhold will be included.  The max matches returned is
   the maximum that fits in a FingerPrintResultsIPv4 class.  */
void match_fingerprint(FingerPrint *FP, FingerPrintResultsIPv4 *FPR,
                      FingerPrintDB *DB, double accuracy_threshold) {
  double FPR_entrance_requirement = accuracy_threshold; /* accuracy must be
                                                           at least this big
                                                           to be added to the
                                                           list */
  std::vector<FingerPrint *>::iterator current_os;
  double acc;
  int state;
  int skipfp;
  int max_prints = sizeof(FPR->matches) / sizeof(FPR->matches[0]);
  int idx;
  double tmp_acc=0.0, tmp_acc2; /* These are temp buffers for list swaps */
  FingerMatch *tmp_FP = NULL, *tmp_FP2;

  assert(FP);
  assert(FPR);
  assert(accuracy_threshold >= 0 && accuracy_threshold <= 1);

  FPR->overall_results = OSSCAN_SUCCESS;

  for (current_os = DB->prints.begin(); current_os != DB->prints.end(); current_os++) {
    skipfp = 0;

    acc = compare_fingerprints(*current_os, FP, DB->MatchPoints, 0);

    /*    error("Comp to %s: %li/%li=%f", o.reference_FPs1[i]->OS_name, num_subtests_succeeded, num_subtests, acc); */
    if (acc >= FPR_entrance_requirement || acc == 1.0) {

      state = 0;
      for (idx=0; idx < FPR->num_matches; idx++) {
        if (strcmp(FPR->matches[idx]->OS_name, (*current_os)->match.OS_name) == 0) {
          if (FPR->accuracy[idx] >= acc) {
            skipfp = 1; /* Skip it -- a higher version is already in list */
          } else {
            /* We must shift the list left to delete this sucker */
            memmove(FPR->matches + idx, FPR->matches + idx + 1,
                    (FPR->num_matches - 1 - idx) * sizeof(FingerPrint *));
            memmove(FPR->accuracy + idx, FPR->accuracy + idx + 1,
                    (FPR->num_matches - 1 - idx) * sizeof(double));
            FPR->num_matches--;
            FPR->accuracy[FPR->num_matches] = 0;
          }
          break; /* There can only be 1 in the list with same name */
        }
      }

      if (!skipfp) {
        /* First we check whether we have overflowed with perfect matches */
        if (acc == 1) {
          /*      error("DEBUG: Perfect match #%d/%d", FPR->num_perfect_matches + 1, max_prints); */
          if (FPR->num_perfect_matches == max_prints) {
            FPR->overall_results = OSSCAN_TOOMANYMATCHES;
            return;
          }
          FPR->num_perfect_matches++;
        }

        /* Now we add the sucker to the list */
        state = 0; /* Have not yet done the insertion */
        for (idx=-1; idx < max_prints -1; idx++) {
          if (state == 1) {
            /* Push tmp_acc and tmp_FP onto the next idx */
            tmp_acc2 = FPR->accuracy[idx+1];
            tmp_FP2 = FPR->matches[idx+1];

            FPR->accuracy[idx+1] = tmp_acc;
            FPR->matches[idx+1] = tmp_FP;

            tmp_acc = tmp_acc2;
            tmp_FP = tmp_FP2;
          } else if (FPR->accuracy[idx + 1] < acc) {
            /* OK, I insert the sucker into the next slot ... */
            tmp_acc = FPR->accuracy[idx+1];
            tmp_FP = FPR->matches[idx+1];
            FPR->matches[idx+1] = &(*current_os)->match;
            FPR->accuracy[idx+1] = acc;
            state = 1;
          }
        }
        if (state != 1) {
          fatal("Bogus list insertion state (%d) -- num_matches = %d num_perfect_matches=%d entrance_requirement=%f", state, FPR->num_matches, FPR->num_perfect_matches, FPR_entrance_requirement);
        }
        FPR->num_matches++;
        /* If we are over max_prints, one was shoved off list */
        if (FPR->num_matches > max_prints)
          FPR->num_matches = max_prints;

        /* Calculate the new min req. */
        if (FPR->num_matches == max_prints) {
          FPR_entrance_requirement = FPR->accuracy[max_prints - 1] + 0.00001;
        }
      }
    }
  }

  if (FPR->num_matches == 0 && FPR->overall_results == OSSCAN_SUCCESS)
    FPR->overall_results = OSSCAN_NOMATCHES;

  return;
}

static const char *dist_method_fp_string(enum dist_calc_method method)
{
  const char *s = "";

  switch (method) {
  case DIST_METHOD_NONE:
    s = "";
    break;
  case DIST_METHOD_LOCALHOST:
    s = "L";
    break;
  case DIST_METHOD_DIRECT:
    s = "D";
    break;
  case DIST_METHOD_ICMP:
    s = "I";
    break;
  case DIST_METHOD_TRACEROUTE:
    s = "T";
    break;
  }

  return s;
}

/* Writes an informational "Test" result suitable for including at the
   top of a fingerprint.  Gives info which might be useful when the
   FPrint is submitted (eg Nmap version, etc).  Result is written (up
   to ostrlen) to the ostr var passed in */
void WriteSInfo(char *ostr, int ostrlen, bool isGoodFP,
                                const char *engine_id,
                                const struct sockaddr_storage *addr, int distance,
                                enum dist_calc_method distance_calculation_method,
                                const u8 *mac, int openTcpPort,
                                int closedTcpPort, int closedUdpPort) {
  struct tm *ltime;
  time_t timep;
  char dsbuf[10], otbuf[8], ctbuf[8], cubuf[8], dcbuf[8];
  char macbuf[16];
  timep = time(NULL);
  ltime = localtime(&timep);

  otbuf[0] = '\0';
  if (openTcpPort != -1)
    Snprintf(otbuf, sizeof(otbuf), "%d", openTcpPort);
  ctbuf[0] = '\0';
  if (closedTcpPort != -1)
    Snprintf(ctbuf, sizeof(ctbuf), "%d", closedTcpPort);
  cubuf[0] = '\0';
  if (closedUdpPort != -1)
    Snprintf(cubuf, sizeof(cubuf), "%d", closedUdpPort);

  dsbuf[0] = '\0';
  if (distance != -1)
    Snprintf(dsbuf, sizeof(dsbuf), "%%DS=%d", distance);
  if (distance_calculation_method != DIST_METHOD_NONE)
    Snprintf(dcbuf, sizeof(dcbuf), "%%DC=%s", dist_method_fp_string(distance_calculation_method));
  else
    dcbuf[0] = '\0';

  macbuf[0] = '\0';
  if (mac)
    Snprintf(macbuf, sizeof(macbuf), "%%M=%02X%02X%02X", mac[0], mac[1], mac[2]);

  Snprintf(ostr, ostrlen, "SCAN(V=%s%%E=%s%%D=%d/%d%%OT=%s%%CT=%s%%CU=%s%%PV=%c%s%s%%G=%c%s%%TM=%X%%P=%s)",
                   NMAP_VERSION, engine_id, ltime->tm_mon + 1, ltime->tm_mday,
                   otbuf, ctbuf, cubuf, isipprivate(addr) ? 'Y' : 'N', dsbuf, dcbuf, isGoodFP ? 'Y' : 'N',
                   macbuf, (int) timep, NMAP_PLATFORM);
}

/* Puts a textual representation of the test in s.
   No more than n bytes will be written. Unless n is 0, the string is always
   null-terminated. Returns the number of bytes written, excluding the
   terminator. */
static int test2str(const FingerTest *test, char *s, size_t n) {
  std::vector<struct AVal>::const_iterator av;
  char *p;
  char *end;
  size_t len;

  if (n == 0)
    return 0;

  p = s;
  end = s + n - 1;

  len = strlen(test->name);
  if (p + len > end)
    goto error;

  memcpy(p, test->name, len);
  p += len;
  if (p + 1 > end)
    goto error;
  *p++ = '(';

  for (av = test->results.begin(); av != test->results.end(); av++) {
    if (av != test->results.begin()) {
      if (p + 1 > end)
        goto error;
      *p++ = '%';
    }
    len = strlen(av->attribute);
    if (p + len > end)
      goto error;
    memcpy(p, av->attribute, len);
    p += len;
    if (p + 1 > end)
      goto error;
    *p++ = '=';
    len = strlen(av->value);
    if (p + len > end)
      goto error;
    memcpy(p, av->value, len);
    p += len;
  }

  if (p + 1 > end)
    goto error;
  *p++ = ')';

  *p = '\0';

  return p - s;

error:
  if (n > 0)
    *s = '\0';

  return -1;
}

static std::vector<struct AVal> str2AVal(const char *str) {
  int i = 1;
  int count = 1;
  const char *q = str, *p=str;
  std::vector<struct AVal> AVs;

  if (!*str)
    return std::vector<struct AVal>();

  /* count the AVals */
  while ((q = strchr(q, '%'))) {
    count++;
    q++;
  }

  AVs.reserve(count);
  for (i = 0; i < count; i++) {
    struct AVal av;

    q = strchr(p, '=');
    if (!q) {
      fatal("Parse error with AVal string (%s) in nmap-os-db file", str);
    }
    av.attribute = string_pool_substr(p, q);
    p = q+1;
    if (i < count - 1) {
      q = strchr(p, '%');
      if (!q) {
        fatal("Parse error with AVal string (%s) in nmap-os-db file", str);
      }
      av.value = string_pool_substr(p, q);
    } else {
      av.value = string_pool_insert(p);
    }
    p = q + 1;
    AVs.push_back(av);
  }

  return AVs;
}

/* Compare two AVal chains literally, without evaluating the value of either one
   as an expression. This is used by mergeFPs. Unlike with AVal_match, it is
   always the case that AVal_match_literal(a, b) == AVal_match_literal(b, a). */
static bool test_match_literal(const FingerTest *a, const FingerTest *b) {
  std::vector<struct AVal>::const_iterator i;
  const struct AVal *av;

  /* Check that b contains all the AVals in a, with the same values. */
  for (i = a->results.begin(); i != a->results.end(); i++) {
    av = b->getattrbyname(i->attribute);
    if (av == NULL || strcmp(i->value, av->value) != 0)
      return false;
  }

  /* Check that a contains all the AVals in b, with the same values. */
  for (i = b->results.begin(); i != b->results.end(); i++) {
    av = a->getattrbyname(i->attribute);
    if (av == NULL || strcmp(i->value, av->value) != 0)
      return false;
  }

  return true;
}

/* This is a less-than relation predicate that establishes the preferred order
   of tests when they are displayed. Returns true if and only if the test a
   should come before the test b. */
static bool FingerTest_lessthan(const FingerTest* a, const FingerTest* b) {
  /* This defines the order in which test lines should appear. */
  const char *TEST_ORDER[] = {
    "SEQ", "OPS", "WIN", "ECN",
    "T1", "T2", "T3", "T4", "T5", "T6", "T7",
    "U1", "IE"
  };
  unsigned int i;
  int ia, ib;

  /* The indices at which the test names were found in the list. -1 means "not
     found." */
  ia = -1;
  ib = -1;
  /* Look up the test names in the list. */
  for (i = 0; i < sizeof(TEST_ORDER) / sizeof(*TEST_ORDER); i++) {
    if (ia == -1 && strcmp(a->name, TEST_ORDER[i]) == 0)
      ia = i;
    if (ib == -1 && strcmp(b->name, TEST_ORDER[i]) == 0)
      ib = i;
    /* Once we've found both tests we can stop searching. */
    if (ia != -1 && ib != -1)
      break;
  }
  /* If a test name was not found, it probably indicates an error in another
     part of the code. */
  if (ia == -1)
    fatal("%s received an unknown test name \"%s\".\n", __func__, a->name);
  if (ib == -1)
    fatal("%s received an unknown test name \"%s\".\n", __func__, b->name);

  return ia < ib;
}

/* Merges the tests from several fingerprints into a character string
   representation. Tests that are identical between more than one fingerprint
   are included only once. If wrapit is true, the string is wrapped for
   submission. */
const char *mergeFPs(FingerPrint *FPs[], int numFPs, bool isGoodFP,
                           const struct sockaddr_storage *addr, int distance,
                           enum dist_calc_method distance_calculation_method,
                           const u8 *mac, int openTcpPort, int closedTcpPort,
                           int closedUdpPort, bool wrapit) {
  static char str[10240];
  static char wrapstr[10240];

  char *p;
  int i;
  char *end = str + sizeof(str) - 1; /* Last byte allowed to write into */
  std::list<const FingerTest *> tests;
  std::list<const FingerTest *>::iterator iter;
  std::vector<FingerTest>::iterator ft;

  if (numFPs <= 0)
    return "(None)";
  else if (numFPs > 32)
    return "(Too many)";

  /* Copy the tests from each fingerprint into a flat list. */
  for (i = 0; i < numFPs; i++) {
    for (ft = FPs[i]->tests.begin(); ft != FPs[i]->tests.end(); ft++)
      tests.push_back(&*ft);
  }

  /* Put the tests in the proper order and ensure that tests with identical
     names are contiguous. */
  tests.sort(FingerTest_lessthan);

  /* Delete duplicate tests to ensure that all the tests are unique. One test is
     a duplicate of the other if it has the same name as the first and the two
     results lists match. */
  for (iter = tests.begin(); iter != tests.end(); iter++) {
    std::list<const FingerTest *>::iterator tmp_i, next;
    tmp_i = iter;
    tmp_i++;
    while (tmp_i != tests.end() && strcmp((*iter)->name, (*tmp_i)->name) == 0) {
      next = tmp_i;
      next++;
      if (test_match_literal(*iter, *tmp_i)) {
        /* This is a duplicate test. Remove it. */
        tests.erase(tmp_i);
      }
      tmp_i = next;
    }
  }

  /* A safety check to make sure that no tests were lost in merging. */
  for (i = 0; i < numFPs; i++) {
    for (ft = FPs[i]->tests.begin(); ft != FPs[i]->tests.end(); ft++) {
      for (iter = tests.begin(); iter != tests.end(); iter++) {
        if (strcmp((*iter)->name, ft->name) == 0 && test_match_literal(*iter, &*ft)) {
            break;
        }
      }
      if (iter == tests.end()) {
        char buf[200];
        test2str(&*ft, buf, sizeof(buf));
        fatal("The test %s was somehow lost in %s.\n", buf, __func__);
      }
    }
  }

  memset(str, 0, sizeof(str));

  p = str;

  /* Lets start by writing the fake "SCAN" test for submitting fingerprints */
  WriteSInfo(p, sizeof(str), isGoodFP, "4", addr, distance, distance_calculation_method, mac, openTcpPort, closedTcpPort, closedUdpPort);
  p = p + strlen(str);
  if (!wrapit)
    *p++ = '\n';

  assert(p <= end);

  /* Append the string representation of each test to the result string. */
  for (iter = tests.begin(); iter != tests.end(); iter++) {
    int len;

    len = test2str(*iter, p, end - p + 1);
    if (len == -1)
      break;
    p += len;
    if (!wrapit) {
      if (p + 1 > end)
        break;
      *p++ = '\n';
    }
  }

  /* If we bailed out of the loop early it was because we ran out of space. */
  if (iter != tests.end())
    fatal("Merged fingerprint too long in %s.\n", __func__);

  *p = '\0';

  if (!wrapit) {
    return str;
  } else {
    /* Wrap the str. */
    int len;
    char *p1 = wrapstr;
    end = wrapstr + sizeof(wrapstr) - 1;

    p = str;

    while (*p && end-p1 >= 3) {
      len = 0;
      strcpy(p1, "OS:"); p1 += 3; len +=3;
      while (*p && len <= FP_RESULT_WRAP_LINE_LEN && end-p1 > 0) {
        *p1++ = *p++;
        len++;
      }
      if (end-p1 <= 0) {
        fatal("Wrapped result too long!\n");
        break;
      }
      *p1++ = '\n';
    }
    *p1 = '\0';

    return wrapstr;
  }
}

const char *fp2ascii(FingerPrint *FP) {
  static char str[2048];
  std::vector<FingerTest>::iterator iter;
  char *p = str;

  if (!FP)
    return "(None)";

  for (iter = FP->tests.begin(); iter != FP->tests.end(); iter++) {
    int len;

    len = test2str(&*iter, p, sizeof(str) - (p - str));
    if (len == -1)
      break;
    p += len;
    if (p + 1 > str + sizeof(str))
      break;
    *p++ = '\n';
  }

  *p = '\0';

  return str;
}

/* Parse a 'Class' line found in the fingerprint file into the current
   FP.  Classno is the number of 'class' lines found so far in the
   current fingerprint.  The function quits if there is a parse error */
static void parse_classline(FingerPrint *FP, char *thisline, int lineno) {
  const char *begin, *end;
  struct OS_Classification os_class;

  if (!thisline || strncmp(thisline, "Class ", 6) != 0)
    fatal("Bogus line #%d (%s) passed to %s()", lineno, thisline, __func__);

  /* First let's get the vendor name. */
  begin = thisline + 6;
  end = strchr(begin, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  os_class.OS_Vendor = string_pool_substr_strip(begin, end);

  /* Next comes the OS family. */
  begin = end + 1;
  end = strchr(begin, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  os_class.OS_Family = string_pool_substr_strip(begin, end);

  /* And now the the OS generation. */
  begin = end + 1;
  end = strchr(begin, '|');
  if (end == NULL)
    fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
  /* OS generation is handled specially: instead of an empty string it's
     supposed to be NULL. */
  while (isspace((int) (unsigned char) *begin))
    begin++;
  if (begin < end)
    os_class.OS_Generation = string_pool_substr_strip(begin, end);
  else
    os_class.OS_Generation = NULL;

  /* And finally the device type. We look for '\0' instead of '|'. */
  begin = end + 1;
  end = strchr(begin, '\0');
  os_class.Device_Type = string_pool_substr_strip(begin, end);

  FP->match.OS_class.push_back(os_class);
}

static void parse_cpeline(FingerPrint *FP, char *thisline, int lineno) {
  const char *cpe;

  if (FP->match.OS_class.empty())
    fatal("\"CPE\" line without preceding \"Class\" at line %d", lineno);

  OS_Classification& osc = FP->match.OS_class.back();

  if (thisline == NULL || strncmp(thisline, "CPE ", 4) != 0)
    fatal("Bogus line #%d (%s) passed to %s()", lineno, thisline, __func__);

  /* The cpe part may be followed by whitespace-separated flags (like "auto"),
     which we ignore. */
  cpe = string_pool_strip_word(thisline + 4);
  assert(cpe != NULL);
  osc.cpe.push_back(cpe);
}

/* Parses a single fingerprint from the memory region given.  If a
   non-null fingerprint is returned, the user is in charge of freeing it
   when done.  This function does not require the fingerprint to be 100%
   complete since it is used by scripts such as scripts/fingerwatch for
   which some partial fingerpritns are OK. */
/* This function is not currently used by Nmap, but it is present here because
   it is used by fingerprint utilities that link with Nmap object files. */
FingerPrint *parse_single_fingerprint(char *fprint_orig) {
  int lineno = 0;
  char *p, *q;
  char *thisline, *nextline;
  char *fprint = strdup(fprint_orig); /* Make a copy we can futz with */
  FingerPrint *FP;

  FP = new FingerPrint;

  thisline = fprint;

  do /* 1 line at a time */ {
    nextline = strchr(thisline, '\n');
    if (nextline)
      *nextline++ = '\0';
    /* printf("Preparing to handle next line: %s\n", thisline); */

    while (*thisline && isspace((int) (unsigned char) *thisline))
      thisline++;
    if (!*thisline) {
      fatal("Parse error on line %d of fingerprint: %s", lineno, nextline);
    }

    if (strncmp(thisline, "Fingerprint ", 12) == 0) {
      /* Ignore a second Fingerprint line if it appears. */
      if (FP->match.OS_name == NULL) {
        p = thisline + 12;
        while (*p && isspace((int) (unsigned char) *p))
          p++;

        q = strchr(p, '\n');
        if (!q)
          q = p + strlen(p);
        while (q > p && isspace((int) (unsigned char) *(--q)))
          ;

        FP->match.OS_name = (char *) cp_alloc(q - p + 2);
        memcpy(FP->match.OS_name, p, q - p + 1);
        FP->match.OS_name[q - p + 1] = '\0';
      }
    } else if (strncmp(thisline, "MatchPoints", 11) == 0) {
      p = thisline + 11;
      if (*p && !isspace((int) (unsigned char) *p))
        fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
      while (*p && isspace((int) (unsigned char) *p))
        p++;
      if (*p != '\0')
        fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
    } else if (strncmp(thisline, "Class ", 6) == 0) {

      parse_classline(FP, thisline, lineno);

    } else if (strncmp(thisline, "CPE ", 4) == 0) {

      parse_cpeline(FP, thisline, lineno);

    } else if ((q = strchr(thisline, '('))) {
      FingerTest test;
      *q = '\0';
      test.name = string_pool_insert(thisline);
      p = q+1;
      *q = '(';
      q = strchr(p, ')');
      if (!q) {
        fatal("Parse error on line %d of fingerprint: %s\n", lineno, thisline);
      }
      *q = '\0';
      test.results = str2AVal(p);
      FP->tests.push_back(test);
    } else {
      fatal("Parse error line #%d of fingerprint: %s", lineno, thisline);
    }

    thisline = nextline; /* Time to handle the next line, if there is one */
    lineno++;
  } while (thisline && *thisline);

  /* Free the temporary fingerprint copy. */
  free(fprint);

  return FP;
}


FingerPrintDB *parse_fingerprint_file(const char *fname) {
  FingerPrintDB *DB = NULL;
  FingerPrint *current;
  FILE *fp;
  char line[2048];
  int lineno = 0;
  bool parsingMatchPoints = false;

  DB = new FingerPrintDB;

  char *p, *q; /* OH YEAH!!!! */

  if (!DB)
    fatal("non-allocated DB passed to %s", __func__);

  fp = fopen(fname, "r");
  if (!fp)
    fatal("Unable to open Nmap fingerprint file: %s", fname);

top:
  while (fgets(line, sizeof(line), fp)) {
    lineno++;
    /* Read in a record */
    if (*line == '\n' || *line == '#')
      continue;

fparse:
    if (strncasecmp(line, "FingerPrint", 11) == 0) {
      parsingMatchPoints = false;
    } else if (strncasecmp(line, "MatchPoints", 11) == 0) {
      if (DB->MatchPoints)
        fatal("Found MatchPoints directive on line %d of %s even though it has previously been seen in the file", lineno, fname);
      parsingMatchPoints = true;
    } else {
      error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
      continue;
    }

    current = new FingerPrint;

    if (parsingMatchPoints) {
      current->match.OS_name = NULL;
      DB->MatchPoints = current;
    } else {
      DB->prints.push_back(current);
      p = line + 12;
      while (*p && isspace((int) (unsigned char) *p))
        p++;

      q = strpbrk(p, "\n#");
      if (!q)
        fatal("Parse error on line %d of fingerprint: %s", lineno, line);

      while (isspace((int) (unsigned char) *(--q)))
        ;

      if (q < p)
        fatal("Parse error on line %d of fingerprint: %s", lineno, line);

      current->match.OS_name = (char *) cp_alloc(q - p + 2);
      memcpy(current->match.OS_name, p, q - p + 1);
      current->match.OS_name[q - p + 1] = '\0';
    }

    current->match.line = lineno;

    /* Now we read the fingerprint itself */
    while (fgets(line, sizeof(line), fp)) {
      lineno++;
      if (*line == '#')
        continue;
      if (*line == '\n')
        break;

      if (!strncmp(line, "FingerPrint ",12)) {
        goto fparse;
      } else if (strncmp(line, "Class ", 6) == 0) {
        parse_classline(current, line, lineno);
      } else if (strncmp(line, "CPE ", 4) == 0) {
        parse_cpeline(current, line, lineno);
      } else {
        FingerTest test;
        p = line;
        q = strchr(line, '(');
        if (!q) {
          error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
          goto top;
        }
        *q = '\0';
        test.name = string_pool_insert(p);
        p = q+1;
        *q = '(';
        q = strchr(p, ')');
        if (!q) {
          error("Parse error on line %d of nmap-os-db file: %s", lineno, line);
          goto top;
        }
        *q = '\0';
        test.results = str2AVal(p);
        current->tests.push_back(test);
      }
    }
  }

  fclose(fp);
  return DB;
}

FingerPrintDB *parse_fingerprint_reference_file(const char *dbname) {
  char filename[256];

  if (nmap_fetchfile(filename, sizeof(filename), dbname) != 1) {
    fatal("OS scan requested but I cannot find %s file.  It should be in %s, ~/.nmap/ or .", dbname, NMAPDATADIR);
  }
  /* Record where this data file was found. */
  o.loaded_data_files[dbname] = filename;

  return parse_fingerprint_file(filename);
}
