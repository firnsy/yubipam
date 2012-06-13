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
* Description:
*   This program is designed to run setuid(root) or with sufficient privilege
* to read all of the Yubikey OTP/passcode databases. It is designed to provide
* a mechanism for the current user (defined by this process' uid) to verify
* their own OTP/passcode.
*
*   The OTP/passcode is read from the standard input. The exit status of this
* program indicates whether the user is authenticated or not.
*
* 
* Acknowlegements:
*   1. This code is derived from the works of Andrew G. Morgan, 1996 in the
*      Linux-PAM project, specfically support.c
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

#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <getopt.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED (selinux_enabled!=-1 ? selinux_enabled : (selinux_enabled=is_selinux_enabled()>0))
static security_context_t prev_context=NULL;
static int selinux_enabled=-1;
#else
#define SELINUX_ENABLED 0
#endif

#define MAXPASS 129 /* the maximum length of a OTP/passcode */

static void su_sighandler(int sig) {
#ifndef SA_RESETHAND
    /* emulate the behaviour of the SA_RESETHAND flag */
    if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV )
        signal(sig, SIG_DFL);
#endif
    if (sig > 0) {
        syslog(LOG_AUTH, "caught signal %d.", sig);
        exit(sig);
    }
}

static void setup_signals(void) {
    struct sigaction action;    /* posix signal structure */

    /*
     * Setup signal handlers
     */
    (void) memset((void *) &action, 0, sizeof(action));
    action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
    action.sa_flags = SA_RESETHAND;
#endif
    (void) sigaction(SIGILL, &action, NULL);
    (void) sigaction(SIGTRAP, &action, NULL);
    (void) sigaction(SIGBUS, &action, NULL);
    (void) sigaction(SIGSEGV, &action, NULL);
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    (void) sigaction(SIGTERM, &action, NULL);
    (void) sigaction(SIGHUP, &action, NULL);
    (void) sigaction(SIGINT, &action, NULL);
    (void) sigaction(SIGQUIT, &action, NULL);
}


static char *getuidname(uid_t uid) {
    struct passwd *pw;
    static char username[32];

    pw = getpwuid(uid);
    if (pw == NULL)
        return NULL;

    strncpy(username, pw->pw_name, sizeof(username));
    username[sizeof(username) - 1] = '\0';

    return username;
}


int _yubi_verify_otp_passcode(char *user, char *otp_passcode, int debug) {
    int i;

    yk_ticket tkt;
    ykdb_entry entry;
    ykdb_h *handle;
    
    char *pch;
    char otp[64] = "";    // max 12-char public-id, 32-char otp
    char passcode[64] = "";

    uint8_t tkt_private_uid_hash[32];

    uint8_t ticket_enc_key[256];
    uint8_t ticket_enc_hash[32];

    uint8_t public_uid_bin[PUBLIC_UID_BYTE_SIZE];
    uint8_t public_uid_bin_size = 0;

    uint32_t crc;
    int delta_session;
    int delta_button;
    int otp_len = 0;
    int passcode_len = 0;

    if (debug)
        syslog(LOG_DEBUG, "received OTP/Passcode: %s", otp_passcode ? otp_passcode:"");

    /* set additional default values for the entry after parsing */
    getSHA256((uint8_t *)user, strlen(user), (uint8_t *)&entry.user_hash);
    
    /* everything upto the first "|" is otp, everything after is passcode */
    if ( NULL != (pch=strchr(otp_passcode, '|')) ) {
        otp_len = pch-otp_passcode;
        passcode_len = strlen(otp_passcode) - otp_len - 1;

        if ( otp_len > 0 )
            strncpy(otp, otp_passcode, otp_len);

        if ( passcode_len > 0 )
            strncpy(passcode, pch+1, passcode_len);
    } else {
        syslog(LOG_AUTH, "invalid otp/passcode received: %s", otp_passcode ? otp_passcode:"");
        return EXIT_FAILURE;
    }
    
    if (debug)
        syslog(LOG_DEBUG, "OTP: %s (%d), Passcode: %s (%d)", otp, otp_len, passcode, passcode_len);

    /* perform initial parse to grab public UID */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (uint8_t *)otp, NULL);
     
    /* OTP needs the public UID for lookup */
    if (public_uid_bin_size <= 0) {
        if (debug)
            syslog(LOG_DEBUG, "public_uid has no length, OTP is invalid");
        return EXIT_FAILURE;
    }

    /* set additional default values for the entry after parsing */
    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
     
    /* open the db or create if empty */
    handle = ykdbDatabaseOpen(CONFIG_AUTH_DB_DEFAULT);
    if (handle == NULL) {
        if (debug)
            syslog(LOG_DEBUG, "couldn't access database: %s", CONFIG_AUTH_DB_DEFAULT);
        return EXIT_FAILURE;
    }
    
    /* seek to public UID if it exists */
    if ( ykdbEntrySeekOnUserPublicHash(handle, (uint8_t *)&entry.user_hash, (uint8_t *)&entry.public_uid_hash, YKDB_SEEK_START) != YKDB_SUCCESS ) {
        ykdbDatabaseClose(handle);
        if (debug)
            syslog(LOG_DEBUG, "no entry for user (with that token): %s", user);
        free(handle);
        return EXIT_FAILURE;
    }

    /* grab the entry */
    if ( ykdbEntryGet(handle, &entry) != YKDB_SUCCESS ) {
        ykdbDatabaseClose(handle);
        free(handle);
        return EXIT_FAILURE;
    }
     
    /* start building decryption entry as required */
    safeSnprintf((char *)ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");
     
    /* add hex string format of public uid */
    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ) {
        safeSnprintfAppend((char *)ticket_enc_key, 256, "|");
        for(i=0; i<public_uid_bin_size; i++)
            safeSnprintfAppend((char *)ticket_enc_key, 256, "%02x", public_uid_bin[i]);
    }
    
    /* add passcode as appropriate */
    if ( (entry.flags & YKDB_TOKEN_ENC_PASSCODE) ) {
        if (passcode_len > 0) {
            safeSnprintfAppend((char *)ticket_enc_key, 256, "|%s", passcode);
        } else {
            /* passcode needed but not given */
            ykdbDatabaseClose(handle);
            free(handle);
            return 128;
        }
    }

    /* close off decryption key text and generate encryption hash */
    safeSnprintfAppend((char *)ticket_enc_key, 256, "|TICKET_ENC_KEY_END");
    if (debug)
        syslog(LOG_DEBUG, "Encryption Key: %s", ticket_enc_key);

    getSHA256(ticket_enc_key, strlen((char *)ticket_enc_key), ticket_enc_hash);
    
    /* decrypt if flags indicate so */
    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
            entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        aesDecryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_hash, ticket_enc_hash+16);
    }
 
    /* perform real parse to grab real ticket, using the now unecrypted key */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (uint8_t *)otp, (uint8_t *)&entry.ticket.key);
 
    /* check CRC matches */
    crc = getCRC((uint8_t *)&tkt, sizeof(yk_ticket));
    ENDIAN_SWAP_16(crc);
 
    /* no use continuing if the decoded OTP failed */
    if ( crc != CRC_OK_RESIDUE ) {
        ykdbDatabaseClose(handle);
        if (debug)
            syslog(LOG_DEBUG, "crc invalid: 0x%04x", crc);
        free(handle);
        return EXIT_FAILURE;
    }

    /* hash decrypted private uid */
    getSHA256(tkt.private_uid, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&tkt_private_uid_hash);
 
    /* match private uid hashes */
    if ( memcmp(&tkt_private_uid_hash, &entry.ticket.private_uid_hash, 32) ) {
        ykdbDatabaseClose(handle);
        if (debug)
            syslog(LOG_DEBUG, "private uid mismatch");
        free(handle);
        return EXIT_FAILURE;
    }

    /* check counter deltas */
    delta_session = tkt.session_counter - entry.ticket.last_session;
    delta_button = tkt.button_counter - entry.ticket.last_button;

    if ( delta_session < 0 ) {
        ykdbDatabaseClose(handle);
        if (debug)
            syslog(LOG_DEBUG, "OTP is INVALID. Session delta: %d. Possible replay!!!", delta_session);
        free(handle);
        return EXIT_FAILURE;
    }
    
    if ( delta_session == 0 && delta_button <= 0 ) {
        ykdbDatabaseClose(handle);
        if (debug)
            syslog(LOG_DEBUG, "OTP is INVALID. Session delta: %d. Button delta: %d. Possible replay!!!", delta_session, delta_button);
        free(handle);
        return EXIT_FAILURE;
    }
    
    /* update the database entry with the latest counters */
    entry.ticket.last_timestamp_lo = tkt.timestamp_lo;
    entry.ticket.last_timestamp_hi = tkt.timestamp_hi;
    entry.ticket.last_session = tkt.session_counter;
    entry.ticket.last_button = tkt.button_counter;

    /* re-encrypt and write to database */
    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
            entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        aesEncryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_hash, ticket_enc_hash+16);
    }

    /* re-encrypt and write to database */
    if ( ykdbEntryWrite(handle, &entry) != YKDB_SUCCESS ) {
        ykdbDatabaseClose(handle);
        free(handle);
        return EXIT_FAILURE;
    }

    free(handle);
    return EXIT_SUCCESS;
}


// Main
int main(int argc, char *argv[]) {
    char pass[MAXPASS + 1];
    int npass;
    int retval = EXIT_FAILURE;
    int debug = 0;
    int ch;
    char *user = NULL;

    /*
     * Catch or ignore as many signal as possible.
     */
    setup_signals();

    /* loop through each command line var and process it */
    while((ch = getopt(argc, argv, "d")) != -1) {
        switch(ch) {
            case 'd': /* Set debug mode on */
                debug = 1;
                break;
        }
    }
    
    /* there should be at least one left over argument */
    if (optind < argc) {
        /* grab the first additional argument as the user name */
        user = strdup(argv[optind]);
    }

    /*
     * we establish that this program is running with non-tty stdin.
     * this is to discourage casual use. It does *NOT* prevent an
     * intruder from repeatadly running this program to determine the
     * OTP/passcode of the current user (brute force attack, but one for
     * which the attacker must already have gained access to the user's
     * account).
     */
    if (isatty(STDIN_FILENO) || user == NULL ) {
        syslog(LOG_AUTH
            ,"inappropriate use of Unix helper binary [UID=%d]"
            ,getuid());
        fprintf(stderr
            ,"This binary is not designed for running in this way\n"
             "-- the system administrator has been informed\n");
        sleep(10);    // this should discourage/annoy the user
        return EXIT_FAILURE;
    }

    /*
     * Determine what the current user's name is.
     * On a SELinux enabled system with a strict policy leaving the
     * existing check prevents shadow password authentication from working.
     * We must thus skip the check if the real uid is 0.
     */
    if (getuid() != 0) {
        /* if the caller specifies the username, verify that user
         matches it */
        if (strcmp(user, getuidname(getuid()))) {
            syslog(LOG_AUTH
                ,"mismatch of %s|%s", user, getuidname(getuid()));
            free(user);
            return EXIT_FAILURE;
        }
    }

    /* read the OTP/passcode from stdin (a pipe from the pam_yubikey module) */
    npass = read(STDIN_FILENO, pass, MAXPASS);

    if (npass < 0) {    /* is it a valid OTP/passcode? */
        syslog(LOG_DEBUG, "no OTP/passcode supplied");
    } else if (npass >= MAXPASS) {
        syslog(LOG_DEBUG, "OTP/passcode too long");
    } else {
        pass[npass] = '\0';    /* NUL terminate */
        retval = _yubi_verify_otp_passcode(user, pass, debug);
    }

    memset(pass, '\0', MAXPASS);    /* clear memory of the OTP/passcode */

    /* return pass or fail */
    if ((retval != EXIT_SUCCESS) && (retval != 128)) {
        syslog(LOG_AUTH, "OTP/passcode check failed for user (%s)", user);
        free(user);
        return EXIT_FAILURE;
    }
    
    free(user);
    return retval;
}

