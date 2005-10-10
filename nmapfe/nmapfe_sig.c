
/***************************************************************************
 * nmapfe_sig.c -- Signal handlers for NmapFE                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://www.insecure.org/nmap/ to download Nmap.                         *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


/* Original Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */

#ifndef MAX_PARSE_ARGS
#define MAX_PARSE_ARGS 512
#endif

#if MISSING_GTK
/* Do nothing, nmapfe.c will spit out an error */
#else

#include <nbase.h>

#include <gtk/gtk.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <fcntl.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>


#ifdef WIN32
#include <windows.h>
#endif

#include "nmapfe.h"
#include "nmapfe_sig.h"

#ifndef BUFSIZ
#define BUFSIZ  8192
#endif


extern struct NmapFEoptions opt;

/* Variables for piping */
/* FIXME: All this should be redone in a much more elegant manner <sigh> */
int nmap_pid = 0;
#ifdef WIN32
HANDLE NmapHandle;
#endif
int pid;
#ifdef WIN32
HANDLE pipes[2]; /* 0 == read; 1 == write */
#else
int pipes[2] = {-1,-1};
#endif
int verb = 0;
extern char **environ;



int main (int argc, char *argv[])
{
GtkWidget *main_win;

  gtk_set_locale();
  gtk_init(&argc, &argv);

#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
  opt.uid = getuid();
#else
  opt.uid = 0; /* With Windows (in general), every user is a Super User! */
#endif

  main_win = create_main_win();
  gtk_widget_show(main_win);

  gtk_text_insert(GTK_TEXT(opt.output), NULL, NULL, NULL,
		  (opt.uid == 0)
		   ? "You are root - All options granted."
		   : "You are *NOT* root - Some options aren't available.", -1);

  gtk_main();
  return 0;
}


void exitNmapFE_cb(GtkButton *button, void *ignored)
{
  /* First we want to kill the Nmap process that is running */
  stop_scan();
  gtk_main_quit();
}


void scanButton_toggled_cb(GtkButton *button, void *ignored)
{
  if(GTK_TOGGLE_BUTTON(button)->active) {
  char *command = build_command();

    if(!(opt.appendLog))
      kill_output(NULL);

    nmap_pid = execute(command);
}
  else {
    if (stop_scan()) {
    static char string[256];

      strcpy(string, "CANCELLED!\n\n");
      print_line(GTK_TEXT(opt.output), string);
}
}
}


void saveLog(char *filename)
{
  if (filename && *filename) {
  FILE *file;

    if ((file = fopen(filename, "w"))) {
    char *text = gtk_editable_get_chars(GTK_EDITABLE(opt.output), 0, -1);

      fputs(text, file);
      fclose(file);

      free(text);
}
}
}


void openLog(char *filename)
{
  if (filename && *filename) {
  FILE *file;
     
    if (!opt.appendLog)
      kill_output(NULL);
	
    if((file = fopen(filename, "r"))) {
    char buf[BUFSIZ+1];

      gtk_text_freeze(GTK_TEXT(opt.output));

      while(fgets(buf, BUFSIZ, file) != NULL)
        print_line(GTK_TEXT(opt.output), buf);

      gtk_text_thaw(GTK_TEXT(opt.output));

      fclose(file);
    }
  }
}


void okButton_clicked_cb(GtkWidget *window, GtkButton *button)
{
char *selected = gtk_file_selection_get_filename(GTK_FILE_SELECTION(window));
void (*action)() = gtk_object_get_data(GTK_OBJECT(window), "NmapFE_action");
GtkEntry *entry = gtk_object_get_data(GTK_OBJECT(window), "NmapFE_entry");
char *filename = gtk_object_get_data(GTK_OBJECT(window), "NmapFE_filename");

  if (filename && selected) {
    strncpy(filename, selected, FILENAME_MAX);
    filename[FILENAME_MAX-1] = '\0';
    if (action)
      (*action)(filename);
    if (entry)
      gtk_entry_set_text(GTK_ENTRY(entry), filename);
  }
}


void kill_output()
{
  gtk_text_backward_delete(GTK_TEXT(opt.output),
                           gtk_text_get_length(GTK_TEXT(opt.output)));
}


/* The idea of execute() is to create an Nmap process running in the background with its stdout
    connected to a pipe we can poll many times per second to collect any new output.  Admittedly 
	there are much more elegant ways to do this, but this is how it works now.  The functions
	return the process ID of nmap.  This process is
	different enough between windows & UNIX that I have two functions for doing it: */
int execute_unix(char *command)
{
#ifdef WIN32
  fatal("The execute_unix function should not be called from Windows!");
  return -1;
#else

  /* Many thanks to Fyodor for helping with the piping */
  if (pipe(pipes) == -1) {
    perror("poopy pipe error");
    exit(1);
  }

  if (!(pid = fork())) {
    char **argv;
    int argc;

    argc = arg_parse(command, &argv);
		
    if (argc <= 0)
      exit(1);
    dup2(pipes[1], 1);
    dup2(pipes[1], 2);
    fcntl(pipes[0], F_SETFL, O_NDELAY);
    if (execvp("nmap", argv) == -1) {
      fprintf(stderr, "Nmap execution failed.  errno=%d (%s)\n", errno, strerror(errno));
      exit(1);
    }
    /*exit(127);*/
  }
  if (pid == -1) {
    fprintf(stderr, "fork() failed.  errno=%d (%s)", errno, strerror(errno));
    pid = 0;
    close(pipes[0]);
    pipes[0] = -1;
  }
  close(pipes[1]);
  pipes[1] = -1;

  return(pid);

#endif
}


/* Parts cribbed from _Win32 System Programming Second Edition_ pp 304 */
int execute_win(char *command)
{
#ifndef WIN32
  fatal("The execute_win function should ONLY be called from Windows!");
  return -1;
#else

/* For pipes[] array:  0 == READ; 1 == WRITE */

/* To ensure pipe handles are inheritable */
SECURITY_ATTRIBUTES PipeSA = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
PROCESS_INFORMATION Nmap_Proc;
STARTUPINFO Nmap_Start;

  GetStartupInfo(&Nmap_Start);

  /* Create our pipe for reading Nmap output */
  if (!CreatePipe(&pipes[0], &pipes[1], &PipeSA, 8196))
    pfatal("execute_win: Failed to create pipes!");

  /* Insure that stdout/stderr for Nmap will go to our pipe */
  Nmap_Start.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  Nmap_Start.hStdError = pipes[1];
  Nmap_Start.hStdOutput = pipes[1];
  Nmap_Start.dwFlags = STARTF_USESTDHANDLES;

  /* Start up Nmap! */
  if (!CreateProcess ( NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &Nmap_Start, &Nmap_Proc))
    pfatal("execute_win: Failed to start Nmap process with command '%s'", command);

  /* I don't care about the thread handle or the write pipe anymore */
  CloseHandle(Nmap_Proc.hThread);
   CloseHandle(pipes[1]);

  /* I'm gonna squirrel away the Nmap process handle in a global variable.
     All this nonsense needs to be redone */
   NmapHandle = Nmap_Proc.hProcess;

  return Nmap_Proc.dwProcessId;

#endif
}

int execute(char *command)
{
#ifdef WIN32
int pid = execute_win(command);
#else
int pid = execute_unix(command);
#endif /* WIN32 */

/* timer for calling our read function to poll for new data 8 times per second */
 gtk_timeout_add(125, read_data, NULL);

  return(pid);
}




char *build_command()
{
int size = 2560; /* this should be long enough ;-) */
static char *command = NULL;
static int command_size = 0;

  /* Find how much to malloc() */
  // size = strlen(gtk_entry_get_text(GTK_ENTRY(opt.range_text))) +
  //   strlen(gtk_entry_get_text(GTK_ENTRY(opt.Decoy))) +
  //   strlen(gtk_entry_get_text(GTK_ENTRY(opt.inputFilename))) +
  //   strlen(gtk_entry_get_text(GTK_ENTRY(opt.SourceDevice)))+
  //   strlen(gtk_entry_get_text(GTK_ENTRY(opt.scanRelay)))+
  //   strlen(gtk_entry_get_text(GTK_ENTRY(opt.targetHost))) +
  //   2560;
  /* We get 60 from the chars required for each option */

  if (size > command_size)
    command = realloc(command, size);

  strcpy(command, "nmap ");
 
  /* select the scan type */
  if (opt.scanValue == CONNECT_SCAN) {
    strcat(command, "-sT ");
  } else if (opt.scanValue == PING_SCAN) {
    strcat(command, "-sP ");
  } else if (opt.scanValue == LIST_SCAN) {
    strcat(command, "-sL ");
  } else if (opt.scanValue == UDP_SCAN) {
    strcat(command, "-sU ");
  } else if (opt.scanValue == FIN_SCAN) {
    strcat(command, "-sF ");
  } else if (opt.scanValue == NULL_SCAN) {
    strcat(command, "-sN ");
  } else if (opt.scanValue == XMAS_SCAN) {
    strcat(command, "-sX ");
  } else if (opt.scanValue == ACK_SCAN) {
    strcat(command, "-sA ");
  } else if (opt.scanValue == WIN_SCAN) {
    strcat(command, "-sW ");
  } else if (opt.scanValue == MAIMON_SCAN) {
    strcat(command, "-sM ");
  } else if (opt.scanValue == PROT_SCAN) {
    strcat(command, "-sO ");
  } else if (opt.scanValue == SYN_SCAN) {
    strcat(command, "-sS ");
  } else if ((opt.scanValue == BOUNCE_SCAN) || (opt.scanValue == IDLE_SCAN)) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.scanRelay));

    if (val) {   
      strcat(command, (opt.scanValue == IDLE_SCAN) ? "-sI " : "-b ");
      strcat(command, (*val) ? val : "127.0.0.1");
      strcat(command, " ");
    }
  }
 
  if (GTK_WIDGET_SENSITIVE(opt.RPCInfo) &&
      GTK_TOGGLE_BUTTON(opt.RPCInfo)->active)
    strcat(command, "-sR ");
   
  if (GTK_WIDGET_SENSITIVE(opt.VersionInfo) &&
      GTK_TOGGLE_BUTTON(opt.VersionInfo)->active)
    strcat(command, "-sV ");

  if (GTK_WIDGET_SENSITIVE(opt.OSInfo) &&
      GTK_TOGGLE_BUTTON(opt.OSInfo)->active)
    strcat(command, "-O ");

  if (GTK_WIDGET_SENSITIVE(opt.protportType)) {
    if (opt.protportValue == FAST_PROTPORT)
      strcat(command, "-F ");
    else if (opt.protportValue == ALL_PROTPORT)
      strcat(command, "-p- ");
    else if (opt.protportValue == GIVEN_PROTPORT) {
    char *val = gtk_entry_get_text(GTK_ENTRY(opt.protportRange));

    if (val && *val) {   
        strcat(command, "-p ");
      strcat(command, val);
        strcat(command, " ");
      }
    }
  }

  if (GTK_TOGGLE_BUTTON(opt.dontPing)->active)
    strcat(command, "-P0 ");
  else {
    if (GTK_WIDGET_SENSITIVE(opt.icmpechoPing) && 
        GTK_TOGGLE_BUTTON(opt.icmpechoPing)->active)
      strcat(command, "-PI ");
    if (GTK_WIDGET_SENSITIVE(opt.icmptimePing) &&
        GTK_TOGGLE_BUTTON(opt.icmptimePing)->active)
      strcat(command, "-PP ");
    if (GTK_WIDGET_SENSITIVE(opt.icmpmaskPing) &&
        GTK_TOGGLE_BUTTON(opt.icmpmaskPing)->active)
      strcat(command, "-PM ");
    if (GTK_WIDGET_SENSITIVE(opt.tcpPing) &&
        GTK_TOGGLE_BUTTON(opt.tcpPing)->active) {
    char *val = gtk_entry_get_text(GTK_ENTRY(opt.tcpPingPorts));

      strcat(command, "-PT");
      if (val && *val)
    strcat(command, val);
      strcat(command, " ");
  }
    if (GTK_WIDGET_SENSITIVE(opt.synPing) &&
        GTK_TOGGLE_BUTTON(opt.synPing)->active) {
    char *val = gtk_entry_get_text(GTK_ENTRY(opt.synPingPorts));

      strcat(command, "-PS");
      if (val && *val)
        strcat(command, val);
      strcat(command, " ");
    }
    if (GTK_WIDGET_SENSITIVE(opt.udpPing) &&
        GTK_TOGGLE_BUTTON(opt.udpPing)->active) {
    char *val = gtk_entry_get_text(GTK_ENTRY(opt.udpPingPorts));

      strcat(command, "-PU");
      if (val && *val)   
      strcat(command, val);
      strcat(command, " ");
    }
  }


  if ((opt.throttleValue != NO_THROTTLE) && (opt.throttleValue != NORMAL_THROTTLE))
    sprintf(command+strlen(command), "-T%u ", opt.throttleValue-THROTTLE_OFFSET);

  if (GTK_TOGGLE_BUTTON(opt.startRtt)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.startRttTime));

    sprintf(command+strlen(command), "--initial_rtt_timeout %d ", val);
  }

  if (GTK_TOGGLE_BUTTON(opt.minRtt)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.minRttTime));

    sprintf(command+strlen(command), "--min_rtt_timeout %d ", val);
    }

  if (GTK_TOGGLE_BUTTON(opt.maxRtt)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.maxRttTime));

    sprintf(command+strlen(command), "--max_rtt_timeout %d ", val);
  }

  if (GTK_TOGGLE_BUTTON(opt.hostTimeout)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.hostTimeoutTime));

    sprintf(command+strlen(command), "--host_timeout %d ", val);
    }

  if (GTK_TOGGLE_BUTTON(opt.scanDelay)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.scanDelayTime));

    sprintf(command+strlen(command), "--scan_delay %d ", val);
  }

  if (GTK_TOGGLE_BUTTON(opt.ipv4Ttl)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.ipv4TtlValue));

    sprintf(command+strlen(command), "--ttl %d ", val);
  }

  if (GTK_TOGGLE_BUTTON(opt.minPar)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.minParSocks));

    sprintf(command+strlen(command), "--min_parallelism %d ", val);
    }

  if (GTK_TOGGLE_BUTTON(opt.maxPar)->active) {
  int val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(opt.maxParSocks));

    sprintf(command+strlen(command), "-M %d ", val);
  }


  if (opt.resolveValue == ALWAYS_RESOLVE)
    strcat(command, "-R ");		
  else if (opt.resolveValue == NEVER_RESOLVE)
    strcat(command, "-n ");		

  if (GTK_WIDGET_SENSITIVE(opt.useDecoy) &&
      GTK_TOGGLE_BUTTON(opt.useDecoy)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.Decoy));

    if (val && *val) {   
      strcat(command, "-D ");
      strcat(command, val);
      strcat(command, " ");
    }
  }

  if (GTK_WIDGET_SENSITIVE(opt.useSourceDevice) &&
      GTK_TOGGLE_BUTTON(opt.useSourceDevice)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.SourceDevice));

    if (val && *val) {   
      strcat(command, "-e ");
      strcat(command, val);
      strcat(command, " ");
    }
  }

  if (GTK_WIDGET_SENSITIVE(opt.useSourceIP) &&
      GTK_TOGGLE_BUTTON(opt.useSourceIP)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.SourceIP));

    if (val && *val) {   
      strcat(command, "-S ");
      strcat(command, val);
      strcat(command, " ");
    }
  }

  if (GTK_WIDGET_SENSITIVE(opt.useSourcePort) &&
      GTK_TOGGLE_BUTTON(opt.useSourcePort)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.SourcePort));

    if (val && *val) {   
      strcat(command, "-g ");
      strcat(command, val);
      strcat(command, " ");
    }
  }

  if (GTK_WIDGET_SENSITIVE(opt.useFragments) &&
      GTK_TOGGLE_BUTTON(opt.useFragments)->active)
    strcat(command, "-f ");

  if (GTK_WIDGET_SENSITIVE(opt.useIPv6) &&
      GTK_TOGGLE_BUTTON(opt.useIPv6)->active)
    strcat(command, "-6 ");

  if (GTK_WIDGET_SENSITIVE(opt.useOrderedPorts) &&
      GTK_TOGGLE_BUTTON(opt.useOrderedPorts)->active)
    strcat(command, "-r ");

  if (GTK_WIDGET_SENSITIVE(opt.useInputFile) &&
      GTK_TOGGLE_BUTTON(opt.useInputFile)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.inputFilename));

    if (val && *val) {   
      strcat(command, "-iL ");
      strcat(command, val);
      strcat(command, " ");
    }
  }

  if (GTK_WIDGET_SENSITIVE(opt.useOutputFile) &&
      GTK_TOGGLE_BUTTON(opt.useOutputFile)->active) {
  char *val = gtk_entry_get_text(GTK_ENTRY(opt.outputFilename));

    if (val && *val) {   
      if (opt.outputFormatValue == NORMAL_OUTPUT)
        strcat(command, "-oN ");
      else if (opt.outputFormatValue == GREP_OUTPUT)
        strcat(command, "-oG ");
      else if (opt.outputFormatValue == XML_OUTPUT)
        strcat(command, "-oX ");
      else if (opt.outputFormatValue == ALL_OUTPUT)
        strcat(command, "-oA ");
      else if (opt.outputFormatValue == SKIDS_OUTPUT)
        strcat(command, "-oS ");
      strcat(command, val);
      strcat(command, " ");

      if (GTK_TOGGLE_BUTTON(opt.outputAppend)->active)
        strcat(command, "--append_output ");
    }
  }
 
  if (opt.verboseValue == V1_VERBOSE)
    strcat(command, "-v ");
  else if (opt.verboseValue == V2_VERBOSE)
    strcat(command, "-vv ");
  else if (opt.verboseValue == D1_VERBOSE)
    strcat(command, "-d ");
  else if (opt.verboseValue == D2_VERBOSE)
    strcat(command, "-d2 ");

  strcat(command, gtk_entry_get_text(GTK_ENTRY(opt.targetHost)));

  return(command);
}

void display_nmap_command()
{
char *command = build_command();

  gtk_entry_set_text(GTK_ENTRY(opt.commandEntry), command);
}


void display_nmap_command_cb(GtkWidget *target_option, void *ignored)
{
  display_nmap_command();
}


void browseButton_pressed_cb(GtkWidget *widget, GtkWidget *text)
{
static char filename[FILENAME_MAX+1] = "";
char *name = gtk_entry_get_text(GTK_ENTRY(text));

  if (name && *name) {
    strncpy(filename, name, FILENAME_MAX);
    filename[FILENAME_MAX] = '\0';
  }

  gtk_widget_show(create_fileSelection("Select File", filename, NULL, GTK_ENTRY(text)));
}


void mainMenu_fcb(int *variable, guint action, GtkWidget *w)
{
static char filename[FILENAME_MAX+1] = "";

  switch (action) {
    case FILEOPEN_MENU:
      gtk_widget_show(create_fileSelection("Open Log", filename, openLog, NULL));
      break;
    case FILESAVE_MENU:
      gtk_widget_show(create_fileSelection("Save Log", filename, saveLog, NULL));
      break;
    case FILEQUIT_MENU:
      stop_scan();
      gtk_main_quit();
      break;
    case VIEWMONO_MENU:
      opt.viewValue = 0;
      break;
    case VIEWCOLOR_MENU:
      opt.viewValue = 1;
      break;
    case VIEWAPPEND_MENU:
      opt.appendLog = (GTK_CHECK_MENU_ITEM(w)->active) ? TRUE : FALSE;
      break;
    case HELPHELP_MENU:
      gtk_widget_show(create_helpDialog());
      break;
    case HELPVERSION_MENU:
      execute("nmap -V");
      break;
    case HELPABOUT_MENU:
      gtk_widget_show(create_aboutDialog());
      break;
    default:
      break;
  }
}


void scanType_changed_fcb(int *variable, guint action, GtkWidget *w)
{	
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

    if ((action == PING_SCAN) || (action == LIST_SCAN)) {
      // gtk_widget_set_sensitive(GTK_WIDGET(opt.protportFrame), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportType), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportLabel), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportRange), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.OSInfo), FALSE);
    } else {
      // gtk_widget_set_sensitive(GTK_WIDGET(opt.protportFrame), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportType), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportLabel),
                               (opt.protportValue == GIVEN_PROTPORT));
      gtk_widget_set_sensitive(GTK_WIDGET(opt.protportRange),
                               (opt.protportValue == GIVEN_PROTPORT));
      gtk_widget_set_sensitive(GTK_WIDGET(opt.OSInfo), TRUE);
    }

    if ((action == PING_SCAN) || (action == LIST_SCAN) || (action == PROT_SCAN)) {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.RPCInfo), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.VersionInfo), FALSE);
    } else {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.RPCInfo), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.VersionInfo), TRUE);
    }

    if ((action == CONNECT_SCAN) || (action == BOUNCE_SCAN)) {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.useDecoy), FALSE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.Decoy), FALSE);
    } else if (opt.uid == 0) {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.useDecoy), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.Decoy), TRUE);
    }

    if ((action != ACK_SCAN) && (action != MAIMON_SCAN) && (action != FIN_SCAN) &&
        (action != SYN_SCAN) && (action != NULL_SCAN) && (action != XMAS_SCAN) &&
        (action != WIN_SCAN))
      gtk_widget_set_sensitive(GTK_WIDGET(opt.useFragments), FALSE);
    else if (opt.uid == 0)
      gtk_widget_set_sensitive(GTK_WIDGET(opt.useFragments), TRUE);

    if ((action == BOUNCE_SCAN) || (action == IDLE_SCAN)) {
      gtk_label_set_text(GTK_LABEL(opt.scanRelayLabel), 
                         (action == BOUNCE_SCAN) ? "Bounce Host:" : "Zombie Host:");
      gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelayLabel), TRUE);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelay), TRUE);
      gtk_widget_grab_focus(GTK_WIDGET(opt.scanRelay));
    } else {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelayLabel), FALSE);
      gtk_label_set_text(GTK_LABEL(opt.scanRelayLabel), "Relay Host:");
      gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelay), FALSE);
    }

    gtk_object_set(GTK_OBJECT(opt.protportFrame), "label",
                   (action == PROT_SCAN) ? "Scanned Protocols" : "Scanned Ports", NULL);
  }

  display_nmap_command();
}


void pingButton_toggled_cb(GtkWidget *ping_button, void *ignored)
{
gboolean status = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ping_button));

  if (ping_button == opt.dontPing) {
  gboolean localstatus = (GTK_TOGGLE_BUTTON(opt.tcpPing)->active) && (!status);

    gtk_widget_set_sensitive(GTK_WIDGET(opt.tcpPing), !status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.tcpPingLabel), localstatus);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.tcpPingPorts), localstatus);
    if (opt.uid == 0) {
      gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpechoPing), !status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpmaskPing), !status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.icmptimePing), !status);

      localstatus = (GTK_TOGGLE_BUTTON(opt.synPing)->active) && (!status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.synPing), !status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingLabel), localstatus);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingPorts), localstatus);

      localstatus = (GTK_TOGGLE_BUTTON(opt.udpPing)->active) && (!status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPing), !status);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingLabel), localstatus);
      gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingPorts), localstatus);
    }
  }
  else if (ping_button == opt.tcpPing) {
    gtk_widget_set_sensitive(GTK_WIDGET(opt.tcpPingLabel), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.tcpPingPorts), status);
  }
  else if ((ping_button == opt.synPing) && (opt.uid == 0)) {
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingLabel), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingPorts), status);
  }
  else if ((ping_button == opt.udpPing) && (opt.uid == 0)) {
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingLabel), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingPorts), status);
  }
  
  display_nmap_command();
}


/* callback for factory generated menu items: set variable to action */
void throttleType_changed_fcb(int *variable, guint action, GtkWidget *w)
{	
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

    display_nmap_command();
  }
}


/* callback for factory generated menu items: set variable to action */
void resolveType_changed_fcb(int *variable, guint action, GtkWidget *w)
{
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

    display_nmap_command();
      } 
}


/* callback for factory generated menu items: set variable to action */
void protportType_changed_fcb(int *variable, guint action, GtkWidget *w)
{
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

    gtk_widget_set_sensitive(GTK_WIDGET(opt.protportLabel), (action == GIVEN_PROTPORT));
    gtk_widget_set_sensitive(GTK_WIDGET(opt.protportRange), (action == GIVEN_PROTPORT));
    if (action == GIVEN_PROTPORT)
      gtk_widget_grab_focus(GTK_WIDGET(opt.protportRange));

    display_nmap_command();
  }
}


/* callback for factory generated menu items: set variable to action */
void verboseType_changed_fcb(int *variable, guint action, GtkWidget *w)
{
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

  display_nmap_command();
}
}


/* callback for factory generated menu items: set variable to action */
void outputFormatType_changed_fcb(int *variable, guint action, GtkWidget *w)
{
  if ((variable != NULL) && (w != NULL)) {
    *variable = action;

    display_nmap_command();
  }
}


/* callback for toggle buttons: control other objects seneistivity */
void toggle_button_set_sensitive_cb(GtkWidget *master, GtkWidget *slave)
{
  if ((master != NULL) && (slave != NULL) && GTK_IS_TOGGLE_BUTTON(master))
    gtk_widget_set_sensitive(GTK_WIDGET(slave), GTK_TOGGLE_BUTTON(master)->active);

  display_nmap_command();
}


void validate_file_change(GtkWidget *button, void *ignored)
{	
gboolean status = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));

  if (button == opt.useInputFile) {
    gtk_widget_set_sensitive(GTK_WIDGET(opt.targetHost), !status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.inputFilename), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.inputBrowse), status);
  } else if (button == opt.useOutputFile) {
    gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFilename), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.outputBrowse), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFormatLabel), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFormatType), status);
    gtk_widget_set_sensitive(GTK_WIDGET(opt.outputAppend), status);
  }

  display_nmap_command();
}


void validate_option_change(GtkWidget *target_option, void *ignored)
{	
gboolean status = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(target_option));

  if ((target_option == opt.useInputFile) && (status))
    gtk_entry_set_text(GTK_ENTRY(opt.targetHost), "");

  display_nmap_command();
}


/* The read_from_pipe functions (UNIX & Win versions) do a non-blocking read from the pipe
   given into the buffer given up to a maximum read length of bufsz.  The number of bytes 
   read is returned.  -1 is returned in the case of heinous error.  Returned buffer is NOT
   NUL terminated */
#ifdef WIN32

static int read_from_pipe(HANDLE pipe, char *buf, int bufsz)
{
int ret;
int count = 0;

/* First lets check if anything is ready for us.
   Note: I don't know if this technique even works! */
  ret = WaitForSingleObject(pipe, 0);
  if ( ret == WAIT_OBJECT_0 ) {
    /* Apparently the pipe is available for reading -- Read up to # of bytes in buffer */
    if (!ReadFile(pipe, buf, bufsz, &count, NULL)) {
      if (GetLastError() != ERROR_BROKEN_PIPE)
	pfatal("ReadFile on Nmap process pipe failed!");
    }
  }
  return count;
}

#else

/* NOTE:  pipefd must be in O_NONBLOCK mode ( via fcntl ) */
static int read_from_pipe(int pipefd, char *buf, int bufsz)
{
int count;

  if (pipefd == -1) return -1;
  count = read(pipefd, buf, bufsz);
  if (count == -1 && errno != EINTR && errno != EAGAIN) {
    pfatal("Failed to read from nmap process pipe");
  }
  return count;
}

#endif /* read_from_pipe Win32/UNIX selector */


/* split buf into first line and remainder by
   copying the first line into line and stripping it from str;
   return the first line from str or NULL if str contains no full line.
   bufsz is the number of chars in buf.
 */
char *next_line(char *buf, int bufsz, char *line)
{
  if ((buf != NULL) && (line != NULL)) {
  char *eol = strchr(buf, '\n');

    if (eol != NULL) {
      char *bol = buf;
    int linelen = MIN(bufsz - 1, eol - buf + 1); // we can't exceed buffer size

      /* copy line including \n to line */
      memcpy(line, buf, linelen);
      line[linelen] = '\0';

      eol = buf + linelen;

      /* remove line from str */
      while (*eol != '\0')
	*bol++ = *eol++;
      *bol = '\0';
      
      return(line);
    }
    return(buf);
  }
  return(NULL);
}


// tokensz is the total size of token in characters
char *next_token(char *buf, char *token, int tokensz)
{
  if ((buf != NULL) && (token != NULL)) {
  int count = (strchr("\t ", *buf) != NULL)
              ? strspn(buf, "\t ")
              : strcspn(buf, "\t ");

    if (count > 0) {
      char *bol = buf;
    char *eol;

      count = MIN(count, tokensz - 1);
      eol = buf+count;

      /* copy token  */
      memcpy(token, buf, count);
      token[count] = '\0';

      /* remove token from str */
      while (*eol != '\0')
        *bol++ = *eol++;
      *bol = '\0';

      return(token);
    }
    return(buf);
  }
  return(NULL);
}


void print_line(GtkText *gtktext, char *line)
{
/* Get fonts ready */
GdkFont *fixed = gdk_fontset_load ("-misc-fixed-medium-r-*-*-*-120-*-*-*-*-*-*");
GdkFont *bold = gdk_fontset_load("-misc-fixed-bold-r-normal-*-*-120-*-*-*-*-*-*");

GdkColormap *cmap = gdk_colormap_get_system();
GdkColor red, blue, green;

  red.red = 0xffff;
  red.green = 0;
  red.blue = 0;	
  if (!gdk_color_alloc(cmap, &red))
    g_error("couldn't allocate red");
  
  blue.red = 0;
  blue.green = 0;
  blue.blue = 0xffff;	
  if (!gdk_color_alloc(cmap, &blue))
    g_error("couldn't allocate blue");
  
  green.red = 0x0000;
  green.green = 0xffff;
  green.blue = 0x0000;	
  if (!gdk_color_alloc(cmap, &green))
    g_error("couldn't allocate green");
  
  if (opt.viewValue == 1) {
  char token[BUFSIZ+1];
  char *str;

    while (((str = next_token(line, token, sizeof(token) / sizeof(*token))) != NULL) && (*str != '\0')) {
      /********* CATCH STUFF ****************************/
      if (strstr(str, "http://") ||
          strstr(str, "PORT") ||
          strstr(str, "PROTOCOL") ||
          strstr(str, "STATE") ||
          strstr(str, "SERVICE") ||
          strstr(str, "VERSION") ||
          strstr(str, "(RPC)") ||
          strstr(str, "OWNER") ||
	  strstr(str, "fingerprint")) {
	gtk_text_insert(gtktext, bold, NULL, NULL, str, -1);
      /********* BEGIN PORT COLOR CODING ****************/
      }else if (strstr(str, "sftp") ||
		strstr(str, "mftp") ||
	  	strstr(str, "bftp") ||
	  	strstr(str, "tftp") ||
	  	strstr(str, "ftp") ||
	  	strstr(str, "NetBus") ||
	  	strstr(str, "kshell") ||
	  	strstr(str, "shell") ||
	  	strstr(str, "klogin") ||
	  	strstr(str, "login") ||
	  	strstr(str, "rtelnet") ||
	  	strstr(str, "telnet") ||
	  	strstr(str, "exec") ||
	  	strstr(str, "ssh") ||
	  	strstr(str, "linuxconf")) {
	gtk_text_insert(gtktext, bold, &red, NULL, str, -1);
      }else if (strstr(str, "imap2") ||
	  	strstr(str, "pop-3") ||
	  	strstr(str, "imap3") ||
	  	strstr(str, "smtps") ||
	  	strstr(str, "smtp") ||
	  	strstr(str, "pop-2")) {
	gtk_text_insert(GTK_TEXT(opt.output), bold, &blue, NULL, str, -1);
      }else if (strstr(str, "systat") ||
	  	strstr(str, "netstat") ||
	  	strstr(str, "cfingerd") ||
	  	strstr(str, "finger") ||
	  	strstr(str, "netbios") ||
	  	strstr(str, "X11") ||
	  	strstr(str, "nfs") ||
	  	strstr(str, "sunrpc") ||
	  	strstr(str, "kpasswds") ||
	  	strstr(str, "https") ||
	  	strstr(str, "http")) {
	gtk_text_insert(gtktext, bold, NULL, NULL, str, -1);
      /******* BEGIN OS COLOR CODING *****************/		
      }else if (strstr(str, "Linux") ||
	  	strstr(str, "FreeBSD") ||
	  	strstr(str, "Win") ||
	  	strstr(str, "MacOS") ||
	  	strstr(str, "OpenBSD") ||
	  	strstr(str, "IRIX") ||
	        strstr(str, "Windows")) {
	gtk_text_insert(gtktext, bold, &green, NULL, str, -1);
      }else{ 
	gtk_text_insert(gtktext, fixed, NULL, NULL, str, -1); 
      }
    }
  } /* END VIEW_TYPE == 1 IF */
		
  else
    gtk_text_insert(gtktext, fixed, NULL, NULL, line, -1);
}


gint read_data(gpointer data)
{
  static char buf[BUFSIZ+1] = "";
  static int buflen = 0;
  char line[BUFSIZ+1];
int count;

#ifdef WIN32
  int rc;
  char *p=NULL, *q=NULL;
#endif /* WIN32 */

  while((count = read_from_pipe(pipes[0], buf+buflen, sizeof(buf) - buflen - 1 )) > 0) {
  char *str;

    /* fprintf(stderr, "\nCount was %d\n", count); */
    buflen += count;
    buf[buflen] = '\0';

#ifdef WIN32
    /* For windows, I have to squeeze \r\n back into \n */
    p = q = buf;
    while(*q) { if (*q == '\r') q++; else *p++ = *q++; }
    *p = '\0';
#endif /* WIN32 */

    for (str = next_line(buf, sizeof(buf) / sizeof(*buf), line); 
         (str != buf) && (str != NULL);
         str = next_line(buf, sizeof(buf) / sizeof(*buf), line)) {
      buflen = strlen(buf);
      print_line(GTK_TEXT(opt.output), str);
    }  
  } 

  /*  fprintf(stderr, "Below loop: Count was %d\n", count); */

  if (buflen > 0) {
  char *str;

    while ((str = next_line(buf, sizeof(buf) / sizeof(*buf), line)) != NULL) {
      buflen = strlen(buf);
      print_line(GTK_TEXT(opt.output), str);
        if (str == buf)
          break;
    }
  }

#ifdef WIN32
  if (nmap_pid) {
    rc = WaitForSingleObject(NmapHandle, 0);
    if (rc == WAIT_FAILED) {
      pfatal("Failed in WaitForSingleObject to see if Nmap process has died");
    }
  }
  if (!nmap_pid || rc == WAIT_OBJECT_0) {
    CloseHandle(NmapHandle);
    CloseHandle(pipes[0]);
    nmap_pid = 0;
    buflen = 0;
    buf[buflen] = '\0';
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.scanButton), 0);
    return 0;
  }
#else
  if (!nmap_pid || (waitpid(0, NULL, WNOHANG) == nmap_pid)) {
    /* fprintf(stderr, "Program gone, dead, kablooey!\n"); */
    nmap_pid = 0;
    if (pipes[0] != -1) {
      close(pipes[0]);
      pipes[0] = -1;
    }
    buflen = 0;
    buf[buflen] = '\0';
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.scanButton), 0);
    return 0;
  }
#endif /* waitpid unix/windoze selector */

  return(1);	
}

gboolean stop_scan()
{
  /*  fprintf(stderr, "stop scan called -- pid == %d\n", nmap_pid); */
  if (nmap_pid) {

#ifdef WIN32
    TerminateProcess(NmapHandle, 1);
    CloseHandle(NmapHandle);
    CloseHandle(pipes[0]);
#else
    kill(nmap_pid, 9);
    if (pipes[0] != -1) {
      close(pipes[0]);
      pipes[0] = -1;
    }
#endif /* Win32/UNIX Selector for killing Nmap */

    nmap_pid = 0;

    return(TRUE);
  }
  return(FALSE);
}

void on_verb_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  /* toggle verb */
  verb = (verb) ? 0 : 1;

  display_nmap_command();
}

/***************************************************************/

/* This function takes a command and the address of an uninitialized
   char ** .  It parses the command (by seperating out whitespace)
   into an argv[] style char **, which it sets the argv parameter to.
   The function returns the number of items filled up in the array
   (argc), or -1 in the case of an error.  This function allocates
   memmory for argv and thus it must be freed -- use argv_parse_free()
   for that.  If arg_parse returns <1, then argv does not need to be freed.
   The returned arrays are always terminated with a NULL pointer */
int arg_parse(const char *command, char ***argv)
{
char **myargv = NULL;
int argc = 0;
char mycommand[4096];
unsigned char *start, *end;
char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1) {      
    return -1;
  }
  myargv = calloc(MAX_PARSE_ARGS + 2, sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while(start && *start) {
    while(*start && isspace(*start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');      
    } else if (!*start) {
      continue;
    } else {
      end = start+1;
      while(*end && !isspace(*end)) {      
	end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else start = end;
  }
  myargv[argc+1] = 0;
  *argv = myargv;
  return argc;
}

/* Free an argv allocated inside arg_parse */
void arg_parse_free(char **argv)
{
char **current;

  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while(*current) {
    free(*current);
    current++;
  }
  free(argv);
}


#endif /* MISSING_GTK */
