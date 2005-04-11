/* This is an implementation of the threads API of POSIX 1003.1-2001.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2003 Pthreads-win32 contributors
 * 
 *      Contact Email: rpj@callisto.canberra.edu.au
 * 
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 * 
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 * 
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 * 
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined( PTHREAD_H )
#define PTHREAD_H

#undef PTW32_LEVEL

#if defined(_POSIX_SOURCE)
#define PTW32_LEVEL 0
/* Early POSIX */
#endif

#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 199309
#undef PTW32_LEVEL
#define PTW32_LEVEL 1
/* Include 1b, 1c and 1d */
#endif

#if defined(INCLUDE_NP)
#undef PTW32_LEVEL
#define PTW32_LEVEL 2
/* Include Non-Portable extensions */
#endif

#define PTW32_LEVEL_MAX 3

#if !defined(PTW32_LEVEL)
#define PTW32_LEVEL PTW32_LEVEL_MAX
/* Include everything */
#endif

#ifdef _UWIN
#   define HAVE_STRUCT_TIMESPEC 1
#   define HAVE_SIGNAL_H	1
#   undef HAVE_CONFIG_H
#   pragma comment(lib, "pthread")
#endif

/*
 * -------------------------------------------------------------
 *
 *
 * Module: pthread.h
 *
 * Purpose:
 *	Provides an implementation of PThreads based upon the
 *	standard:
 *
 *		POSIX 1003.1-2001
 *  and
 *    The Single Unix Specification version 3
 *
 *    (these two are equivalent)
 *
 *	in order to enhance code portability between Windows,
 *  various commercial Unix implementations, and Linux.
 *
 *	See the ANNOUNCE file for a full list of conforming
 *	routines and defined constants, and a list of missing
 *	routines and constants not defined in this implementation.
 *
 * Authors:
 *	There have been many contributors to this library.
 *	The initial implementation was contributed by
 *	John Bossom, and several others have provided major
 *	sections or revisions of parts of the implementation.
 *	Often significant effort has been contributed to
 *	find and fix important bugs and other problems to
 *	improve the reliability of the library, which sometimes
 *	is not reflected in the amount of code which changed as
 *	result.
 *	As much as possible, the contributors are acknowledged
 *	in the ChangeLog file in the source code distribution
 *	where their changes are noted in detail.
 *
 *	Contributors are listed in the CONTRIBUTORS file.
 *
 *	As usual, all bouquets go to the contributors, and all
 *	brickbats go to the project maintainer.
 *
 * Maintainer:
 *	The code base for this project is coordinated and
 *	eventually pre-tested, packaged, and made available by
 *
 *		Ross Johnson <rpj@ise.canberra.edu.au>
 *
 * QA Testers:
 *	Ultimately, the library is tested in the real world by
 *	a host of competent and demanding scientists and
 *	engineers who report bugs and/or provide solutions
 *	which are then fixed or incorporated into subsequent
 *	versions of the library. Each time a bug is fixed, a
 *	test case is written to prove the fix and ensure
 *	that later changes to the code don't reintroduce the
 *	same error. The number of test cases is slowly growing
 *	and therefore so is the code reliability.
 *
 * Compliance:
 *	See the file ANNOUNCE for the list of implemented
 *	and not-implemented routines and defined options.
 *	Of course, these are all defined is this file as well.
 *
 * Web site:
 *	The source code and other information about this library
 *	are available from
 *
 *		http://sources.redhat.com/pthreads-win32/
 *
 * -------------------------------------------------------------
 */

/* Try to avoid including windows.h */
#if defined(__MINGW32__) && defined(__cplusplus)
/*
 * FIXME: The pthreadGCE.dll build gets linker unresolved errors
 * on pthread_key_create() unless windows.h is included here.
 * It appears to have something to do with an argument type mismatch.
 * Looking at tsd.o with 'nm' shows this line:
 * 00000000 T _pthread_key_create__FPP14pthread_key_t_PFPv_v
 * instead of
 * 00000000 T _pthread_key_create
 */
#define PTW32_INCLUDE_WINDOWS_H
#endif

#ifdef PTW32_INCLUDE_WINDOWS_H
#include <windows.h>
#endif

/*
 * -----------------
 * autoconf switches
 * -----------------
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#if PTW32_LEVEL >= PTW32_LEVEL_MAX

/* Try to avoid including windows.h */
#if defined(__MINGW32__) && defined(__cplusplus)
/*
 * FIXME: The pthreadGCE.dll build gets linker unresolved errors
 * on pthread_key_create() unless windows.h is included here.
 * It appears to have something to do with an argument type mismatch.
 * Looking at tsd.o with 'nm' shows this line:
 * 00000000 T _pthread_key_create__FPP14pthread_key_t_PFPv_v
 * instead of
 * 00000000 T _pthread_key_create
 */
#define PTW32_INCLUDE_WINDOWS_H
#endif

#ifdef PTW32_INCLUDE_WINDOWS_H
#include <windows.h>
#endif

#ifndef NEED_FTIME
#include <time.h>
#else /* NEED_FTIME */
/* use native WIN32 time API */
#endif /* NEED_FTIME */

#if HAVE_SIGNAL_H
#include <signal.h>
#endif /* HAVE_SIGNAL_H */

#include <setjmp.h>
#include <limits.h>

/*
 * Boolean values to make us independent of system includes.
 */
enum {
  PTW32_FALSE = 0,
  PTW32_TRUE = (! PTW32_FALSE)
};

/*
 * This is a duplicate of what is in the autoconf config.h,
 * which is only used when building the pthread-win32 libraries.
 */

#ifndef PTW32_CONFIG_H
#  if defined(WINCE)
#    define NEED_ERRNO
#    define NEED_SEM
#  endif
#  if defined(_UWIN) || defined(__MINGW32__)
#    define HAVE_MODE_T
#  endif
#endif

/*
 *
 */

#if PTW32_LEVEL >= PTW32_LEVEL_MAX
#ifdef NEED_ERRNO
#include "need_errno.h"
#else
#include <errno.h>
#endif
#endif /* PTW32_LEVEL >= PTW32_LEVEL_MAX */

/*
 * Several systems don't define ENOTSUP. If not, we use
 * the same value as Solaris.
 */
#ifndef ENOTSUP
#  define ENOTSUP 48
#endif

#ifndef ETIMEDOUT
#  define ETIMEDOUT 10060     /* This is the value in winsock.h. */
#endif

#include <sched.h>

/*
 * To avoid including windows.h we define only those things that we
 * actually need from it. I don't like the potential incompatibility that
 * this creates with future versions of windows.
 */
#ifndef PTW32_INCLUDE_WINDOWS_H
#ifndef HANDLE
# define PTW32__HANDLE_DEF
# define HANDLE void *
#endif
#ifndef DWORD
# define PTW32__DWORD_DEF
# define DWORD unsigned long
#endif
#endif

#endif /* PTW32_LEVEL >= PTW32_LEVEL_MAX */

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
	long tv_sec;
	long tv_nsec;
};
#endif /* HAVE_STRUCT_TIMESPEC */

#ifndef SIG_BLOCK
#define SIG_BLOCK 0
#endif /* SIG_BLOCK */

#ifndef SIG_UNBLOCK 
#define SIG_UNBLOCK 1
#endif /* SIG_UNBLOCK */

#ifndef SIG_SETMASK
#define SIG_SETMASK 2
#endif /* SIG_SETMASK */

#ifdef __cplusplus
extern "C"
{
#endif				/* __cplusplus */

/*
 * -------------------------------------------------------------
 *
 * POSIX 1003.1-2001 Options
 * =========================
 *
 * _POSIX_THREADS (set)
 *			If set, you can use threads
 *
 * _POSIX_THREAD_ATTR_STACKSIZE (set)
 *			If set, you can control the size of a thread's
 *			stack
 *				pthread_attr_getstacksize
 *				pthread_attr_setstacksize
 *
 * _POSIX_THREAD_ATTR_STACKADDR (not set)
 *			If set, you can allocate and control a thread's
 *			stack. If not supported, the following functions
 *			will return ENOSYS, indicating they are not
 *			supported:
 *				pthread_attr_getstackaddr
 *				pthread_attr_setstackaddr
 *
 * _POSIX_THREAD_PRIORITY_SCHEDULING (set)
 *			If set, you can use realtime scheduling.
 *			Indicates the availability of:
 *				pthread_attr_getinheritsched
 *				pthread_attr_getschedparam
 *				pthread_attr_getschedpolicy
 *				pthread_attr_getscope
 *				pthread_attr_setinheritsched
 *				pthread_attr_setschedparam
 *				pthread_attr_setschedpolicy
 *				pthread_attr_setscope
 *				pthread_getschedparam
 *				pthread_setschedparam
 *				sched_get_priority_max
 *				sched_get_priority_min
 *				sched_rr_set_interval
 *
 * _POSIX_THREAD_PRIO_INHERIT (not set)
 *			If set, you can create priority inheritance
 *			mutexes.
 *				pthread_mutexattr_getprotocol +
 *				pthread_mutexattr_setprotocol +
 *
 * _POSIX_THREAD_PRIO_PROTECT (not set)
 *			If set, you can create priority ceiling mutexes
 *			Indicates the availability of:
 *				pthread_mutex_getprioceiling
 *				pthread_mutex_setprioceiling
 *				pthread_mutexattr_getprioceiling
 *				pthread_mutexattr_getprotocol	  +
 *				pthread_mutexattr_setprioceiling
 *				pthread_mutexattr_setprotocol	  +
 *
 * _POSIX_THREAD_PROCESS_SHARED (not set)
 *			If set, you can create mutexes and condition
 *			variables that can be shared with another
 *			process.If set, indicates the availability
 *			of:
 *				pthread_mutexattr_getpshared
 *				pthread_mutexattr_setpshared
 *				pthread_condattr_getpshared
 *				pthread_condattr_setpshared
 *
 * _POSIX_THREAD_SAFE_FUNCTIONS (set)
 *			If set you can use the special *_r library
 *			functions that provide thread-safe behaviour
 *
 * _POSIX_READER_WRITER_LOCKS (set)
 *			If set, you can use read/write locks
 *
 * _POSIX_SPIN_LOCKS (set)
 *			If set, you can use spin locks
 *
 * _POSIX_BARRIERS (set)
 *			If set, you can use barriers
 *
 *	+ These functions provide both 'inherit' and/or
 *	  'protect' protocol, based upon these macro
 *	  settings.
 *
 * POSIX 1003.1-2001 Limits
 * ===========================
 *
 * PTHREAD_DESTRUCTOR_ITERATIONS
 *			Maximum number of attempts to destroy
 *			a thread's thread-specific data on
 *			termination (must be at least 4)
 *
 * PTHREAD_KEYS_MAX
 *			Maximum number of thread-specific data keys
 *			available per process (must be at least 128)
 *
 * PTHREAD_STACK_MIN
 *			Minimum supported stack size for a thread
 *
 * PTHREAD_THREADS_MAX
 *			Maximum number of threads supported per
 *			process (must be at least 64).
 *
 * _POSIX_SEM_NSEMS_MAX
 *	The maximum number of semaphores a process can have.
 *	(only defined if not already defined)
 *
 * _POSIX_SEM_VALUE_MAX
 *	The maximum value a semaphore can have.
 *	(only defined if not already defined)
 *
 * -------------------------------------------------------------
 */

/*
 * POSIX Options
 */
#ifndef _POSIX_THREADS
#define _POSIX_THREADS
#endif

#ifndef _POSIX_READER_WRITER_LOCKS
#define _POSIX_READER_WRITER_LOCKS
#endif

#ifndef _POSIX_SPIN_LOCKS
#define _POSIX_SPIN_LOCKS
#endif

#ifndef _POSIX_BARRIERS
#define _POSIX_BARRIERS
#endif

#define _POSIX_THREAD_SAFE_FUNCTIONS
#define _POSIX_THREAD_ATTR_STACKSIZE
#define _POSIX_THREAD_PRIORITY_SCHEDULING

#if defined( KLUDGE )
/*
 * The following are not supported
 */
#define _POSIX_THREAD_ATTR_STACKADDR
#define _POSIX_THREAD_PRIO_INHERIT
#define _POSIX_THREAD_PRIO_PROTECT
#define _POSIX_THREAD_PROCESS_SHARED

#endif				/* KLUDGE */

/*
 * POSIX Limits
 *
 *	PTHREAD_DESTRUCTOR_ITERATIONS
 *		Standard states this must be at least
 *		4.
 *
 *	PTHREAD_KEYS_MAX
 *		WIN32 permits only 64 TLS keys per process.
 *		This limitation could be worked around by
 *		simply simulating keys.
 *
 *	PTHREADS_STACK_MIN
 *		POSIX specifies 0 which is also the value WIN32
 *		interprets as allowing the system to
 *		set the size to that of the main thread. The
 *		maximum stack size in Win32 is 1Meg. WIN32
 *		allocates more stack as required up to the 1Meg
 *		limit.
 *
 *	PTHREAD_THREADS_MAX
 *		Not documented by WIN32. Wrote a test program
 *		that kept creating threads until it failed
 *		revealed this approximate number (Windows NT).
 *		This number is somewhat less for Windows 9x
 *		and is effectively less than 64. Perhaps this
 *		constant should be set at DLL load time.
 *
 */
#define PTHREAD_DESTRUCTOR_ITERATIONS			       4
#define PTHREAD_KEYS_MAX			64
#define PTHREAD_STACK_MIN			 0
#define PTHREAD_THREADS_MAX		      2019
#ifndef _POSIX_SEM_NSEMS_MAX
/* Not used and only an arbitrary value. */
#  define _POSIX_SEM_NSEMS_MAX		      1024
#endif
#ifndef _POSIX_SEM_VALUE_MAX
#  define _POSIX_SEM_VALUE_MAX	       (INT_MAX/2)
#endif

#if __GNUC__ && ! defined (__declspec)
# error Please upgrade your GNU compiler to one that supports __declspec.
#endif

/*
 * When building the DLL code, you should define PTW32_BUILD so that
 * the variables/functions are exported correctly. When using the DLL,
 * do NOT define PTW32_BUILD, and then the variables/functions will
 * be imported correctly.
 */
#ifdef _DLL
#  ifdef PTW32_BUILD
#    define PTW32_DLLPORT __declspec (dllexport)
#  else
#    define PTW32_DLLPORT __declspec (dllimport)
#  endif
#endif

#if defined(_UWIN) && PTW32_LEVEL >= PTW32_LEVEL_MAX
#   include	<sys/types.h>
#else
typedef struct pthread_t_ *pthread_t;
typedef struct pthread_attr_t_ *pthread_attr_t;
typedef struct pthread_once_t_ pthread_once_t;
typedef struct pthread_key_t_ *pthread_key_t;
typedef struct pthread_mutex_t_ *pthread_mutex_t;
typedef struct pthread_mutexattr_t_ *pthread_mutexattr_t;
typedef struct pthread_cond_t_ *pthread_cond_t;
typedef struct pthread_condattr_t_ *pthread_condattr_t;
#endif
typedef struct pthread_rwlock_t_ *pthread_rwlock_t;
typedef struct pthread_rwlockattr_t_ *pthread_rwlockattr_t;
typedef struct pthread_spinlock_t_ *pthread_spinlock_t;
typedef struct pthread_barrier_t_ *pthread_barrier_t;
typedef struct pthread_barrierattr_t_ *pthread_barrierattr_t;

/*
 * ====================
 * ====================
 * POSIX Threads
 * ====================
 * ====================
 */

enum {
/*
 * pthread_attr_{get,set}detachstate
 */
  PTHREAD_CREATE_JOINABLE	= 0,  /* Default */
  PTHREAD_CREATE_DETACHED	= 1,

/*
 * pthread_attr_{get,set}inheritsched
 */
  PTHREAD_INHERIT_SCHED 	= 0,
  PTHREAD_EXPLICIT_SCHED	= 1,  /* Default */

/*
 * pthread_{get,set}scope
 */
  PTHREAD_SCOPE_PROCESS 	= 0,
  PTHREAD_SCOPE_SYSTEM		= 1,  /* Default */

/*
 * pthread_setcancelstate paramters
 */
  PTHREAD_CANCEL_ENABLE 	= 0,  /* Default */
  PTHREAD_CANCEL_DISABLE	= 1,

/*
 * pthread_setcanceltype parameters
 */
  PTHREAD_CANCEL_ASYNCHRONOUS	= 0,
  PTHREAD_CANCEL_DEFERRED	= 1,  /* Default */

/*
 * pthread_mutexattr_{get,set}pshared
 * pthread_condattr_{get,set}pshared
 */
  PTHREAD_PROCESS_PRIVATE	= 0,
  PTHREAD_PROCESS_SHARED	= 1,

/*
 * pthread_barrier_wait
 */
  PTHREAD_BARRIER_SERIAL_THREAD = -1
};

/*
 * ====================
 * ====================
 * Cancelation
 * ====================
 * ====================
 */
#define PTHREAD_CANCELED       ((void *) -1)


/*
 * ====================
 * ====================
 * Once Key
 * ====================
 * ====================
 */
#define PTHREAD_ONCE_INIT	{ PTW32_FALSE, -1 }

struct pthread_once_t_
{
  int done;		    /* indicates if user function executed  */
  long started; 	    /* First thread to increment this value */
			    /* to zero executes the user function   */
};


/*
 * ====================
 * ====================
 * Object initialisers
 * ====================
 * ====================
 */
#define PTHREAD_MUTEX_INITIALIZER ((pthread_mutex_t) -1)

#define PTHREAD_COND_INITIALIZER ((pthread_cond_t) -1)

#define PTHREAD_RWLOCK_INITIALIZER ((pthread_rwlock_t) -1)

#define PTHREAD_SPINLOCK_INITIALIZER ((pthread_spinlock_t) -1)


/*
 * Mutex types.
 */
enum
{
  /* Compatibility with LinuxThreads */
  PTHREAD_MUTEX_FAST_NP,
  PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_TIMED_NP = PTHREAD_MUTEX_FAST_NP,
  PTHREAD_MUTEX_ADAPTIVE_NP = PTHREAD_MUTEX_FAST_NP,
  /* For compatibility with POSIX */
  PTHREAD_MUTEX_NORMAL = PTHREAD_MUTEX_FAST_NP,
  PTHREAD_MUTEX_RECURSIVE = PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK = PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_DEFAULT = PTHREAD_MUTEX_NORMAL
};


/* There are three implementations of cancel cleanup.
 * Note that pthread.h is included in both application
 * compilation units and also internally for the library.
 * The code here and within the library aims to work
 * for all reasonable combinations of environments.
 *
 * The three implementations are:
 *
 *   WIN32 SEH
 *   C
 *   C++
 *
 * Please note that exiting a push/pop block via
 * "return", "exit", "break", or "continue" will
 * lead to different behaviour amongst applications
 * depending upon whether the library was built
 * using SEH, C++, or C. For example, a library built
 * with SEH will call the cleanup routine, while both
 * C++ and C built versions will not.
 */

/*
 * Define defaults for cleanup code.
 * Note: Unless the build explicitly defines one of the following, then
 * we default to standard C style cleanup. This style uses setjmp/longjmp
 * in the cancelation and thread exit implementations and therefore won't
 * do stack unwinding if linked to applications that have it (e.g.
 * C++ apps). This is currently consistent with most/all commercial Unix
 * POSIX threads implementations.
 */
#if !defined( __CLEANUP_SEH ) && !defined( __CLEANUP_CXX ) && !defined( __CLEANUP_C )
# define __CLEANUP_C
#endif

#if defined( __CLEANUP_SEH ) && defined(__GNUC__)
#error ERROR [__FILE__, line __LINE__]: GNUC does not support SEH.
#endif

typedef struct ptw32_cleanup_t ptw32_cleanup_t;
typedef void (__cdecl *ptw32_cleanup_callback_t)(void *);

struct ptw32_cleanup_t
{
  ptw32_cleanup_callback_t routine;
  void *arg;
  struct ptw32_cleanup_t *prev;
};

#ifdef __CLEANUP_SEH
	/*
	 * WIN32 SEH version of cancel cleanup.
	 */

#define pthread_cleanup_push( _rout, _arg ) \
	{ \
	    ptw32_cleanup_t	_cleanup; \
	    \
	_cleanup.routine	= (ptw32_cleanup_callback_t)(_rout); \
	    _cleanup.arg	= (_arg); \
	    __try \
	      { \

#define pthread_cleanup_pop( _execute ) \
	      } \
	    __finally \
		{ \
		    if( _execute || AbnormalTermination()) \
		      { \
			  (*(_cleanup.routine))( _cleanup.arg ); \
		      } \
		} \
	}

#else /* __CLEANUP_SEH */

#ifdef __CLEANUP_C

	/*
	 * C implementation of PThreads cancel cleanup
	 */

#define pthread_cleanup_push( _rout, _arg ) \
	{ \
	    ptw32_cleanup_t	_cleanup; \
	    \
	    ptw32_push_cleanup( &_cleanup, (ptw32_cleanup_callback_t) (_rout), (_arg) ); \

#define pthread_cleanup_pop( _execute ) \
	    (void) ptw32_pop_cleanup( _execute ); \
	}

#else /* __CLEANUP_C */

#ifdef __CLEANUP_CXX

	/*
	 * C++ version of cancel cleanup.
	 * - John E. Bossom.
	 */

	class PThreadCleanup {
	  /*
	   * PThreadCleanup
	   *
	   * Purpose
	   *	  This class is a C++ helper class that is
	   *	  used to implement pthread_cleanup_push/
	   *	  pthread_cleanup_pop.
	   *	  The destructor of this class automatically
	   *	  pops the pushed cleanup routine regardless
	   *	  of how the code exits the scope
	   *	  (i.e. such as by an exception)
	   */
      ptw32_cleanup_callback_t cleanUpRout;
	  void	  *	  obj;
	  int		  executeIt;

	public:
	  PThreadCleanup() :
	    cleanUpRout( 0 ),
	    obj( 0 ),
	    executeIt( 0 )
	    /*
	     * No cleanup performed
	     */
	    {
	    }

	  PThreadCleanup(
	     ptw32_cleanup_callback_t routine,
			 void	 *	 arg ) :
	    cleanUpRout( routine ),
	    obj( arg ),
	    executeIt( 1 )
	    /*
	     * Registers a cleanup routine for 'arg'
	     */
	    {
	    }

	  ~PThreadCleanup()
	    {
	      if ( executeIt && ((void *) cleanUpRout != (void *) 0) )
		{
		  (void) (*cleanUpRout)( obj );
		}
	    }

	  void execute( int exec )
	    {
	      executeIt = exec;
	    }
	};

	/*
	 * C++ implementation of PThreads cancel cleanup;
	 * This implementation takes advantage of a helper
	 * class who's destructor automatically calls the
	 * cleanup routine if we exit our scope weirdly
	 */
#define pthread_cleanup_push( _rout, _arg ) \
	{ \
	    PThreadCleanup  cleanup((ptw32_cleanup_callback_t)(_rout), \
				    (void *) (_arg) );

#define pthread_cleanup_pop( _execute ) \
	    cleanup.execute( _execute ); \
	}

#else

#error ERROR [__FILE__, line __LINE__]: Cleanup type undefined.

#endif /* __CLEANUP_CXX */

#endif /* __CLEANUP_C */

#endif /* __CLEANUP_SEH */

/*
 * ===============
 * ===============
 * Methods
 * ===============
 * ===============
 */

/*
 * PThread Attribute Functions
 */
PTW32_DLLPORT int pthread_attr_init (pthread_attr_t * attr);

PTW32_DLLPORT int pthread_attr_destroy (pthread_attr_t * attr);

PTW32_DLLPORT int pthread_attr_getdetachstate (const pthread_attr_t * attr,
					 int *detachstate);

PTW32_DLLPORT int pthread_attr_getstackaddr (const pthread_attr_t * attr,
				       void **stackaddr);

PTW32_DLLPORT int pthread_attr_getstacksize (const pthread_attr_t * attr,
				       size_t * stacksize);

PTW32_DLLPORT int pthread_attr_setdetachstate (pthread_attr_t * attr,
					 int detachstate);

PTW32_DLLPORT int pthread_attr_setstackaddr (pthread_attr_t * attr,
				       void *stackaddr);

PTW32_DLLPORT int pthread_attr_setstacksize (pthread_attr_t * attr,
				       size_t stacksize);

PTW32_DLLPORT int pthread_attr_getschedparam (const pthread_attr_t *attr,
					struct sched_param *param);

PTW32_DLLPORT int pthread_attr_setschedparam (pthread_attr_t *attr,
					const struct sched_param *param);

PTW32_DLLPORT int pthread_attr_setschedpolicy (pthread_attr_t *,
					 int);

PTW32_DLLPORT int pthread_attr_getschedpolicy (pthread_attr_t *,
					 int *);

PTW32_DLLPORT int pthread_attr_setinheritsched(pthread_attr_t * attr,
					 int inheritsched);

PTW32_DLLPORT int pthread_attr_getinheritsched(pthread_attr_t * attr,
					 int * inheritsched);

PTW32_DLLPORT int pthread_attr_setscope (pthread_attr_t *,
				   int);

PTW32_DLLPORT int pthread_attr_getscope (const pthread_attr_t *,
				   int *);

/*
 * PThread Functions
 */
PTW32_DLLPORT int pthread_create (pthread_t * tid,
			    const pthread_attr_t * attr,
			    void *(*start) (void *),
			    void *arg);

PTW32_DLLPORT int pthread_detach (pthread_t tid);

PTW32_DLLPORT int pthread_equal (pthread_t t1,
			   pthread_t t2);

PTW32_DLLPORT void pthread_exit (void *value_ptr);

PTW32_DLLPORT int pthread_join (pthread_t thread,
			  void **value_ptr);

PTW32_DLLPORT pthread_t pthread_self (void);

PTW32_DLLPORT int pthread_cancel (pthread_t thread);

PTW32_DLLPORT int pthread_setcancelstate (int state,
				    int *oldstate);

PTW32_DLLPORT int pthread_setcanceltype (int type,
				   int *oldtype);

PTW32_DLLPORT void pthread_testcancel (void);

PTW32_DLLPORT int pthread_once (pthread_once_t * once_control,
			  void (*init_routine) (void));

#if PTW32_LEVEL >= PTW32_LEVEL_MAX
PTW32_DLLPORT ptw32_cleanup_t *ptw32_pop_cleanup (int execute);

PTW32_DLLPORT void ptw32_push_cleanup (ptw32_cleanup_t * cleanup,
				 void (*routine) (void *),
				 void *arg);
#endif /* PTW32_LEVEL >= PTW32_LEVEL_MAX */

/*
 * Thread Specific Data Functions
 */
PTW32_DLLPORT int pthread_key_create (pthread_key_t * key,
				void (*destructor) (void *));

PTW32_DLLPORT int pthread_key_delete (pthread_key_t key);

PTW32_DLLPORT int pthread_setspecific (pthread_key_t key,
				 const void *value);

PTW32_DLLPORT void *pthread_getspecific (pthread_key_t key);


/*
 * Mutex Attribute Functions
 */
PTW32_DLLPORT int pthread_mutexattr_init (pthread_mutexattr_t * attr);

PTW32_DLLPORT int pthread_mutexattr_destroy (pthread_mutexattr_t * attr);

PTW32_DLLPORT int pthread_mutexattr_getpshared (const pthread_mutexattr_t
					  * attr,
					  int *pshared);

PTW32_DLLPORT int pthread_mutexattr_setpshared (pthread_mutexattr_t * attr,
					  int pshared);

PTW32_DLLPORT int pthread_mutexattr_settype (pthread_mutexattr_t * attr, int kind);
PTW32_DLLPORT int pthread_mutexattr_gettype (pthread_mutexattr_t * attr, int *kind);

/*
 * Barrier Attribute Functions
 */
PTW32_DLLPORT int pthread_barrierattr_init (pthread_barrierattr_t * attr);

PTW32_DLLPORT int pthread_barrierattr_destroy (pthread_barrierattr_t * attr);

PTW32_DLLPORT int pthread_barrierattr_getpshared (const pthread_barrierattr_t
					    * attr,
					    int *pshared);

PTW32_DLLPORT int pthread_barrierattr_setpshared (pthread_barrierattr_t * attr,
					    int pshared);

/*
 * Mutex Functions
 */
PTW32_DLLPORT int pthread_mutex_init (pthread_mutex_t * mutex,
				const pthread_mutexattr_t * attr);

PTW32_DLLPORT int pthread_mutex_destroy (pthread_mutex_t * mutex);

PTW32_DLLPORT int pthread_mutex_lock (pthread_mutex_t * mutex);

PTW32_DLLPORT int pthread_mutex_timedlock(pthread_mutex_t *mutex,
				    const struct timespec *abstime);

PTW32_DLLPORT int pthread_mutex_trylock (pthread_mutex_t * mutex);

PTW32_DLLPORT int pthread_mutex_unlock (pthread_mutex_t * mutex);

/*
 * Spinlock Functions
 */
PTW32_DLLPORT int pthread_spin_init (pthread_spinlock_t * lock, int pshared);

PTW32_DLLPORT int pthread_spin_destroy (pthread_spinlock_t * lock);

PTW32_DLLPORT int pthread_spin_lock (pthread_spinlock_t * lock);

PTW32_DLLPORT int pthread_spin_trylock (pthread_spinlock_t * lock);

PTW32_DLLPORT int pthread_spin_unlock (pthread_spinlock_t * lock);

/*
 * Barrier Functions
 */
PTW32_DLLPORT int pthread_barrier_init (pthread_barrier_t * barrier,
				  const pthread_barrierattr_t * attr,
				  unsigned int count);

PTW32_DLLPORT int pthread_barrier_destroy (pthread_barrier_t * barrier);

PTW32_DLLPORT int pthread_barrier_wait (pthread_barrier_t * barrier);

/*
 * Condition Variable Attribute Functions
 */
PTW32_DLLPORT int pthread_condattr_init (pthread_condattr_t * attr);

PTW32_DLLPORT int pthread_condattr_destroy (pthread_condattr_t * attr);

PTW32_DLLPORT int pthread_condattr_getpshared (const pthread_condattr_t * attr,
					 int *pshared);

PTW32_DLLPORT int pthread_condattr_setpshared (pthread_condattr_t * attr,
					 int pshared);

/*
 * Condition Variable Functions
 */
PTW32_DLLPORT int pthread_cond_init (pthread_cond_t * cond,
			       const pthread_condattr_t * attr);

PTW32_DLLPORT int pthread_cond_destroy (pthread_cond_t * cond);

PTW32_DLLPORT int pthread_cond_wait (pthread_cond_t * cond,
			       pthread_mutex_t * mutex);

PTW32_DLLPORT int pthread_cond_timedwait (pthread_cond_t * cond,
				    pthread_mutex_t * mutex,
				    const struct timespec *abstime);

PTW32_DLLPORT int pthread_cond_signal (pthread_cond_t * cond);

PTW32_DLLPORT int pthread_cond_broadcast (pthread_cond_t * cond);

/*
 * Scheduling
 */
PTW32_DLLPORT int pthread_setschedparam (pthread_t thread,
				   int policy,
				   const struct sched_param *param);

PTW32_DLLPORT int pthread_getschedparam (pthread_t thread,
				   int *policy,
				   struct sched_param *param);

PTW32_DLLPORT int pthread_setconcurrency (int);
 
PTW32_DLLPORT int pthread_getconcurrency (void);

/*
 * Read-Write Lock Functions
 */
PTW32_DLLPORT int pthread_rwlock_init(pthread_rwlock_t *lock,
				const pthread_rwlockattr_t *attr);

PTW32_DLLPORT int pthread_rwlock_destroy(pthread_rwlock_t *lock);

PTW32_DLLPORT int pthread_rwlock_tryrdlock(pthread_rwlock_t *);

PTW32_DLLPORT int pthread_rwlock_trywrlock(pthread_rwlock_t *);

PTW32_DLLPORT int pthread_rwlock_rdlock(pthread_rwlock_t *lock);

PTW32_DLLPORT int pthread_rwlock_timedrdlock(pthread_rwlock_t *lock,
				       const struct timespec *abstime);

PTW32_DLLPORT int pthread_rwlock_wrlock(pthread_rwlock_t *lock);

PTW32_DLLPORT int pthread_rwlock_timedwrlock(pthread_rwlock_t *lock,
				       const struct timespec *abstime);

PTW32_DLLPORT int pthread_rwlock_unlock(pthread_rwlock_t *lock);

PTW32_DLLPORT int pthread_rwlockattr_init (pthread_rwlockattr_t * attr);

PTW32_DLLPORT int pthread_rwlockattr_destroy (pthread_rwlockattr_t * attr);

PTW32_DLLPORT int pthread_rwlockattr_getpshared (const pthread_rwlockattr_t * attr,
					   int *pshared);

PTW32_DLLPORT int pthread_rwlockattr_setpshared (pthread_rwlockattr_t * attr,
					   int pshared);

#if PTW32_LEVEL >= PTW32_LEVEL_MAX - 1

/*
 * Signal Functions. Should be defined in <signal.h> but MSVC and MinGW32
 * already have signal.h that don't define these.
 */
PTW32_DLLPORT int pthread_kill(pthread_t thread, int sig);

/*
 * Non-portable functions
 */

/*
 * Compatibility with Linux.
 */
PTW32_DLLPORT int pthread_mutexattr_setkind_np(pthread_mutexattr_t * attr,
					 int kind);
PTW32_DLLPORT int pthread_mutexattr_getkind_np(pthread_mutexattr_t * attr,
					 int *kind);

/*
 * Possibly supported by other POSIX threads implementations
 */
PTW32_DLLPORT int pthread_delay_np (struct timespec * interval);
PTW32_DLLPORT int pthread_num_processors_np(void);

/*
 * Useful if an application wants to statically link
 * the lib rather than load the DLL at run-time.
 */
PTW32_DLLPORT int pthread_win32_process_attach_np(void);
PTW32_DLLPORT int pthread_win32_process_detach_np(void);
PTW32_DLLPORT int pthread_win32_thread_attach_np(void);
PTW32_DLLPORT int pthread_win32_thread_detach_np(void);

/*
 * Register a system time change with the library.
 * Causes the library to perform various functions
 * in response to the change. Should be called whenever
 * the application's top level window receives a
 * WM_TIMECHANGE message. It can be passed directly to
 * pthread_create() as a new thread if desired.
 */
PTW32_DLLPORT void * pthread_timechange_handler_np(void *);

#endif /*PTW32_LEVEL >= PTW32_LEVEL_MAX - 1 */

#if PTW32_LEVEL >= PTW32_LEVEL_MAX

/*
 * Returns the Win32 HANDLE for the POSIX thread.
 */
PTW32_DLLPORT HANDLE pthread_getw32threadhandle_np(pthread_t thread);


/*
 * Protected Methods
 *
 * This function blocks until the given WIN32 handle
 * is signaled or pthread_cancel had been called.
 * This function allows the caller to hook into the
 * PThreads cancel mechanism. It is implemented using
 *
 *		WaitForMultipleObjects
 *
 * on 'waitHandle' and a manually reset WIN32 Event
 * used to implement pthread_cancel. The 'timeout'
 * argument to TimedWait is simply passed to
 * WaitForMultipleObjects.
 */
PTW32_DLLPORT int pthreadCancelableWait (HANDLE waitHandle);
PTW32_DLLPORT int pthreadCancelableTimedWait (HANDLE waitHandle,
					DWORD timeout);

#endif /* PTW32_LEVEL >= PTW32_LEVEL_MAX */

/*
 * Thread-Safe C Runtime Library Mappings.
 */
#ifndef _UWIN
#  if defined(NEED_ERRNO)
     PTW32_DLLPORT int * _errno( void );
#  else
#    ifndef errno
#      if (defined(_MT) || defined(_DLL))
	 __declspec(dllimport) extern int * __cdecl _errno(void);
#	 define errno	(*_errno())
#      endif
#    endif
#  endif
#endif

/*
 * WIN32 C runtime library had been made thread-safe
 * without affecting the user interface. Provide
 * mappings from the UNIX thread-safe versions to
 * the standard C runtime library calls.
 * Only provide function mappings for functions that
 * actually exist on WIN32.
 */

#if !defined(__MINGW32__)
#define strtok_r( _s, _sep, _lasts ) \
	( *(_lasts) = strtok( (_s), (_sep) ) )
#endif /* !__MINGW32__ */

#define asctime_r( _tm, _buf ) \
	( strcpy( (_buf), asctime( (_tm) ) ), \
	  (_buf) )

#define ctime_r( _clock, _buf ) \
	( strcpy( (_buf), ctime( (_clock) ) ),	\
	  (_buf) )

#define gmtime_r( _clock, _result ) \
	( *(_result) = *gmtime( (_clock) ), \
	  (_result) )

#define localtime_r( _clock, _result ) \
	( *(_result) = *localtime( (_clock) ), \
	  (_result) )

#define rand_r( _seed ) \
	( _seed == _seed? rand() : rand() )


#ifdef __cplusplus

/*
 * Internal exceptions
 */
class ptw32_exception {};
class ptw32_exception_cancel : public ptw32_exception {};
class ptw32_exception_exit   : public ptw32_exception {};

#endif

#if PTW32_LEVEL >= PTW32_LEVEL_MAX

/* FIXME: This is only required if the library was built using SEH */
/*
 * Get internal SEH tag
 */
PTW32_DLLPORT DWORD ptw32_get_exception_services_code(void);

#endif /* PTW32_LEVEL >= PTW32_LEVEL_MAX */

#ifndef PTW32_BUILD

#ifdef __CLEANUP_SEH

/*
 * Redefine the SEH __except keyword to ensure that applications
 * propagate our internal exceptions up to the library's internal handlers.
 */
#define __except( E ) \
	__except( ( GetExceptionCode() == ptw32_get_exception_services_code() ) \
		 ? EXCEPTION_CONTINUE_SEARCH : ( E ) )

#endif /* __CLEANUP_SEH */

#ifdef __CLEANUP_CXX

/*
 * Redefine the C++ catch keyword to ensure that applications
 * propagate our internal exceptions up to the library's internal handlers.
 */
#ifdef _MSC_VER
	/*
	 * WARNING: Replace any 'catch( ... )' with 'PtW32CatchAll'
	 * if you want Pthread-Win32 cancelation and pthread_exit to work.
	 */

#ifndef PtW32NoCatchWarn

#pragma message("Specify \"/DPtW32NoCatchWarn\" compiler flag to skip this message.")
#pragma message("------------------------------------------------------------------")
#pragma message("When compiling applications with MSVC++ and C++ exception handling:")
#pragma message("  Replace any 'catch( ... )' in routines called from POSIX threads")
#pragma message("  with 'PtW32CatchAll' or 'CATCHALL' if you want POSIX thread")
#pragma message("  cancelation and pthread_exit to work. For example:")
#pragma message("")
#pragma message("    #ifdef PtW32CatchAll")
#pragma message("      PtW32CatchAll")
#pragma message("    #else")
#pragma message("      catch(...)")
#pragma message("    #endif")
#pragma message("	 {")
#pragma message("	   /* Catchall block processing */")
#pragma message("	 }")
#pragma message("------------------------------------------------------------------")

#endif

#define PtW32CatchAll \
	catch( ptw32_exception & ) { throw; } \
	catch( ... )

#else /* _MSC_VER */

#define catch( E ) \
	catch( ptw32_exception & ) { throw; } \
	catch( E )

#endif /* _MSC_VER */

#endif /* __CLEANUP_CXX */

#endif /* ! PTW32_BUILD */

#ifdef __cplusplus
}				/* End of extern "C" */
#endif				/* __cplusplus */

#ifdef PTW32__HANDLE_DEF
# undef HANDLE
#endif
#ifdef PTW32__DWORD_DEF
# undef DWORD
#endif

#undef PTW32_LEVEL
#undef PTW32_LEVEL_MAX

#endif /* PTHREAD_H */
