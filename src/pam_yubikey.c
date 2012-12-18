/*
* YubiKey PAM Module
*
* Copyright (C) 2012 Jeroen Nijhof <jeroen@jeroennijhof.nl>
* Copyright (C) 2008-2010 Ian Firns <firnsy@securixlive.com>
* Copyright (C) 2008-2010 SecurixLive <dev@securixlive.com>
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
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

#ifndef __linux__
    #include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#ifndef PAM_EXTERN
    #ifdef PAM_STATIC
        #define PAM_EXTERN static
    #else
        #define PAM_EXTERN extern
    #endif
#endif

#ifdef WITH_SELINUX
    #include <selinux/selinux.h>
    #define SELINUX_ENABLED is_selinux_enabled()>0
#else
    #define SELINUX_ENABLED 0
#endif


int user_in_usersfile(char *usersfile, const char *user, int debug) {
    FILE* fp = fopen( usersfile, "r" );

    if ( fp == NULL ) {
        syslog(LOG_ERR, "unable to open usersfile: %s: %s", usersfile, strerror(errno));
    } else {
        char *c, line[64];
        while (fgets(line, 64, fp)) {
            c = index(line, '\n');
            if( c ) *c = 0;
            if(strcmp(line, user) == 0) {
                if (debug)
                    syslog(LOG_DEBUG, "user found");
                return 1;
            }
        }
        if (debug)
            syslog(LOG_DEBUG, "user not found");
    }

    // User not found or error
    return 0;
}

char *get_response(pam_handle_t *pamh, const char *prompt, const char *user, int verbose) {
    struct pam_conv *conv;
    int retval;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    char *response;
    char buffer[512];

    retval = pam_get_item(pamh, PAM_CONV, (const void**) &conv);
    if (retval != PAM_SUCCESS) {
        return NULL;
    }

    /* check if we want verbose input */
    if ( verbose != 0 )
        msg.msg_style = PAM_PROMPT_ECHO_ON;
    else
        msg.msg_style = PAM_PROMPT_ECHO_OFF;

    sprintf (buffer, "%s (%s): ", prompt, user);

    /* set up the conversation */
    msg.msg = buffer;
    msgp = &msg;
    retval = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

    if (resp == NULL) 
        return NULL;

    if (retval != PAM_SUCCESS) {
        free(resp->resp);
        free(resp);
        return NULL;
    }

    response = resp->resp;
	
    free(resp);
    return response;
}


PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh,
		     int flags, int argc, const char** argv) {
    int retval = 0;
    const char *user = NULL;
    char *otp = NULL;
    char *passcode = NULL;
    char otp_passcode[128];
    int i = 0;
    int debug = 0;
    int verbose_otp = 0;
    char *include_users = NULL;
    char *exclude_users = NULL;
    int passcode_only = 0;

    for (i=0; i<argc; i++) {
        if (strncmp(argv[i], "debug", 5) == 0)
            debug = 1;
        else if (strncmp(argv[i], "verbose_otp", 11) == 0)
            verbose_otp = 1;
        else if (strncmp(argv[i], "include_users=", 14) == 0)
            include_users = index(argv[i], '=') + 1;
        else if (strncmp(argv[i], "exclude_users=", 14) == 0)
            exclude_users = index(argv[i], '=') + 1;
        else if (strncmp(argv[i], "passcode_only", 13) == 0)
            passcode_only = 1;
        if (debug)
            syslog(LOG_DEBUG, "argv[%d]=%s", i, argv[i]);
    }
    if (debug) {
        syslog(LOG_DEBUG, "called.");
        syslog(LOG_DEBUG, "flags %d argc %d", flags, argc);
        syslog(LOG_DEBUG, "verbose=%d", verbose_otp);
    }

    /* obtain the user requesting authentication */
    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
        if (debug)
            syslog(LOG_DEBUG, "get user returned error: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if (debug)
        syslog(LOG_DEBUG, "get user returned: %s", user);

    /* check for include_users and exclude_users */
    if (include_users != NULL) {
        if (!user_in_usersfile(include_users, user, debug)) {
            return PAM_AUTH_ERR;
        }
    }
    if (exclude_users != NULL) {
        if (user_in_usersfile(exclude_users, user, debug)) {
            return PAM_AUTH_ERR;
        }
    }

    /* prompt for the Yubikey OTP (always) */
    otp = get_response(pamh, "Yubikey OTP", user, verbose_otp);

    snprintf(otp_passcode, 128, "%s|", otp ? otp:"");
    if (debug)
        syslog(LOG_DEBUG, "pass: %s (%d)", otp_passcode, (int)strlen(otp_passcode));

    retval = _yubi_run_helper_binary(otp_passcode, user, debug);

    if (retval == YK_PASSCODE) {
        /* need passcode */
        passcode = get_response(pamh, "Yubikey passcode", user, 0);

        snprintf(otp_passcode, 128, "%s|%s", otp ? otp:"", passcode ? passcode:"");
        if (debug)
            syslog(LOG_DEBUG, "pass: %s (%d)", otp_passcode, (int)strlen(otp_passcode));

        retval = _yubi_run_helper_binary(otp_passcode, user, debug);
    }

    if (retval == EXIT_SUCCESS) {
        if ((passcode_only != 0) && (passcode != NULL)) {
            retval = pam_set_item(pamh, PAM_AUTHTOK, passcode);
        } else {
            retval = pam_set_item(pamh, PAM_AUTHTOK, otp_passcode);
        }
        if (retval != PAM_SUCCESS) {
            if (debug)
                syslog(LOG_DEBUG, "set_item returned error: %s", pam_strerror (pamh, retval));
            return retval;
        }
        return PAM_SUCCESS;
    }
    
    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
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

