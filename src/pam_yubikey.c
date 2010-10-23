/*
* YubiKey PAM Module
*
* Copyright (C) 2008-2010 Ian Firns      <firnsy@securixlive.com>
* Copyright (C) 2008-2010 SecurixLive    <dev@securixlive.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
* http://www.gnu.org/copyleft/gpl.html
*
*
* Acknowlegements:
*   1. This code is derived from the works of Cristian Gafton 1996, 
*      Alex O. Yuriev, 1996, Andrew G. Morgan 1996-8, Jan Rêkorajski 1999 in
*      the Linux-PAM project, specfically unik_chkpwd.c
*   2. This addition was intiated by Geoff Hoff
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "libyubipam.h"

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#if defined(DEBUG) && defined(HAVE_SECURITY__PAM_MACROS_H)
#include <security/_pam_macros.h>
#else
#define D(x)			/* nothing */
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

char *get_response(pam_handle_t *, const char *, const char *, int);
static int _yubi_run_helper_binary(pam_handle_t *, const char *, const char *);

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh,
		     int flags, int argc, const char** argv)
{
	int					retval, rc;
	const char			*user = NULL;
    char                *otp;
    char                *passcode;
    char                otp_passcode[128];
	int					i;
	int					delta_session;
	int					delta_button;
	int					nargs = 1;
	int					verbose_otp = 0;
	int					two_factor = 0;

	D (("called."));
	D (("flags %d argc %d", flags, argc));
	for (i=0; i<argc; i++)
	{
		D (("argv[%d]=%s", i, argv[i]));
		if (strncmp(argv[i], "verbose_otp", 11) == 0)
			verbose_otp = 1;
		else if (strncmp(argv[i], "two_factor", 10) == 0)
			two_factor = 1;
	}
	D (("verbose=%d", verbose_otp));

	/* obtain the user requesting authentication */
	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
    {
		D (("get user returned error: %s", pam_strerror (pamh, retval)));
		return retval;
    }
	
	D (("get user returned: %s", user));

	/* prompt for the Yubikey OTP (always) */
	{
		otp = get_response(pamh, "Yubikey OTP", user, verbose_otp);
	}

	/* prompt for the second factor passcode as required */
	if ( two_factor)
    {
    	passcode = get_response(pamh, "Yubikey Passcode", user, 0);
	}

    snprintf(otp_passcode, 128, "%s|%s", otp ? otp:"", passcode ? passcode:"");

    D (("pass: %s (%d)", otp_passcode, strlen(otp_passcode)));

	retval = pam_set_item(pamh, PAM_AUTHTOK, otp_passcode);

	if (retval != PAM_SUCCESS)
	{
		D (("set_item returned error: %s", pam_strerror (pamh, retval)));
		return retval;
	}
    
 	retval =  _yubi_run_helper_binary(pamh, otp_passcode, user);
 	return retval;
  
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

char *get_response(pam_handle_t *pamh, const char *prompt, const char *user, int verbose)
{	
	struct pam_conv				*conv;
	int							retval;
	struct pam_message			msg;
	const struct pam_message	*msgp;
	struct pam_response			*resp;
	char						*response;
	char						buffer[512];

	retval = pam_get_item(pamh, PAM_CONV, (const void**) &conv);
	if (retval != PAM_SUCCESS)
	{
		D (("get conv returned error: %s", pam_strerror (pamh, retval)));
		return NULL;
	}

	/* check if we want verbose input */
	if ( verbose != 0 )
		msg.msg_style = PAM_PROMPT_ECHO_ON;
	else
		msg.msg_style = PAM_PROMPT_ECHO_OFF;

	/* ensure user knows when debugging is turned on */
#ifdef DEBUG
	sprintf (buffer, "DEBUG MODE!!! %s (%s): ", prompt, user);
#else
	sprintf (buffer, "%s (%s): ", prompt, user);
#endif

	/* set up the conversation */
	msg.msg = buffer;
	msgp = &msg;
	retval = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

	if (resp == NULL) 
		return NULL;

	if (retval != PAM_SUCCESS)
	{
		D (("conv returned error: %s", pam_strerror (pamh, retval)));
		free(resp->resp);
		free( resp );
		return NULL;
	}

	D (("conv returned: %s", resp->resp));

	response = resp->resp;
	
	free( resp );
	return response;
}


#ifdef PAM_STATIC

struct pam_module _pam_yubikey_modstruct = {
	"pam_yubikey",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL
};

#endif

/*
 * verify the OTP/passcode of a user
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED is_selinux_enabled()>0
#else
#define SELINUX_ENABLED 0
#endif

#define CHKPWD_HELPER "/sbin/yk_chkpwd"

#define MAX_FD_NO 10000

// this code is from Linux-PAM pam_unix support.c
static int _yubi_run_helper_binary(pam_handle_t *pamh, const char *otp_passcode, const char *user)
{
    int					retval;
	int					child;
	int					fds[2];
    void				(*sighandler)(int) = NULL;

    D(("called."));

    /* create a pipe for the OTP/passcode */
    if (pipe(fds) != 0)
	{
		D(("could not make pipe"));
		return PAM_AUTH_ERR;
    }

#if 0
    // this code is from Linux-PAM pam_unix support.c
    if (off(UNIX_NOREAP, ctrl)) {
	/*
	 * This code arranges that the demise of the child does not cause
	 * the application to receive a signal it is not expecting - which
	 * may kill the application or worse.
	 *
	 * The "noreap" module argument is provided so that the admin can
	 * override this behavior.
	 */
	sighandler = signal(SIGCHLD, SIG_DFL);
    }
#else
	sighandler = signal(SIGCHLD, SIG_DFL);
#endif

    /* fork */
    child = fork();
    if (child == 0)
	{
        int				i = 0;
        struct rlimit	rlim;
		static char		*envp[] = { NULL };
		char			*args[] = { NULL, NULL, NULL, NULL };

		/* XXX - should really tidy up PAM here too */
		
		/* reopen stdin as pipe */
		dup2(fds[0], STDIN_FILENO);
	
		if ( getrlimit(RLIMIT_NOFILE, &rlim)==0 )
		{
            if (rlim.rlim_max >= MAX_FD_NO)
                rlim.rlim_max = MAX_FD_NO;

			for (i=0; i<(int)rlim.rlim_max; i++)
			{
				if (i != STDIN_FILENO)
					close(i);
			}
		}
	
		if (geteuid() == 0)
		{
			/* must set the real uid to 0 so the helper will not error */
		    /* out if pam is called from setuid binary (su, sudo...)   */
			setuid(0);
		}
	
		/* exec binary helper */
		args[0] = strdup(CHKPWD_HELPER);
		args[1] = strdup(user);
	
		execve(CHKPWD_HELPER, args, envp);
	
		/* should not get here: exit with error */
		D(("helper binary is not available"));
		exit(PAM_AUTHINFO_UNAVAIL);
    }
	else if (child > 0)
	{
		/* wait for child */
		/* if the stored OTP/passcode is NULL */
        int				rc = 0;

		if (otp_passcode != NULL) 	/* send the OTP/passcode to the child */
		{
		    if ( write(fds[1], otp_passcode, strlen(otp_passcode)+1) == -1 )
            {
		        D(("cannot send OTP/passcode to helper"));
                close(fds[1]);
                retval = PAM_AUTH_ERR;
            }
		    otp_passcode = NULL;
		}
		else
		{
		    if ( write(fds[1], "", 1) == -1 )              /* blank OTP/passcode */
            {
		        D(("cannot send OTP/passcode to helper"));
                close(fds[1]);
                retval = PAM_AUTH_ERR;
            }
		}

		close(fds[0]);       /* close here to avoid possible SIGPIPE above */
		close(fds[1]);

		rc = waitpid(child, &retval, 0);  /* wait for helper to complete */

		if (rc < 0)
		{
#ifdef HAVE_SECURITY_PAM_EXT_H
			pam_syslog(pamh, LOG_ERR, "yk_chkpwd waitpid returned %d: %m", rc);
#endif
			D(("yk_chkpwd waitpid returned %d: %m", rc));
			retval = PAM_AUTH_ERR;
		}
		else
		{
			retval = WEXITSTATUS(retval);
		}
    }
	else
	{
		D(("fork failed"));
		close(fds[0]);
	 	close(fds[1]);
		retval = PAM_AUTH_ERR;
    }

    if (sighandler != SIG_ERR)
	{
        (void) signal(SIGCHLD, sighandler);   /* restore old signal handler */
    }

    D(("returning %d", retval));
    return retval;
}

