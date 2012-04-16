/*
* YubiKey PAM Passwd Module
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
*/

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include "libyubipam.h"
#include "ykpasswd.h"

#include "errno.h"

char *otp;
char *user_text;
char *public_uid_text = NULL;
char *private_uid_text = NULL;
char *key_text = NULL;
char *passcode_text = NULL;

uint8_t public_uid_bin[PUBLIC_UID_BYTE_SIZE];
uint8_t public_uid_bin_size = 0;
uint8_t key_bin[KEY_BYTE_SIZE];
uint8_t private_uid_bin[PRIVATE_UID_BYTE_SIZE];
uint8_t private_uid_bin_size = 0;

int mode;
ykdb_entry entry;
ykdb_h *handle;
yk_ticket tkt;
char dbname[512] = CONFIG_AUTH_DB_DEFAULT;

extern int ykdb_errno;
extern uint32_t hexDecode(uint8_t *dst, const uint8_t *src, uint32_t dst_size);

void clean(void) {
    /* free any and all allocated memory */
    free(handle);
    free(otp);
    free(user_text);
    free(public_uid_text);
    free(private_uid_text);
    free(passcode_text);
}

static char *valid_options = "hadD:cf:k:o:p:V";

int showUsage(char *program_name) {
    fprintf(stdout, "USAGE: %s [OPTION]... USER\n", program_name);
    fprintf(stdout, "\n");
    fprintf(stdout, "   -h          Show this information\n");
    fprintf(stdout, "   -a          Add yubikey to database\n");
    fprintf(stdout, "   -d          Delete yubikey from database\n");
    fprintf(stdout, "   -D <path>   Explicitly define the database <path>\n");
    fprintf(stdout, "   -c          Prompt for second factor pass code\n");
    fprintf(stdout, "   -f <uid>    Fixed (Public) UID in hex\n");
    fprintf(stdout, "   -k <key>    AES key in hex\n");
    fprintf(stdout, "   -o <otp>    Yubikey generated OTP\n");
    fprintf(stdout, "   -p <uid>    Private UID in hex\n");
    fprintf(stdout, "   -V          Show version and exit\n");
    fprintf(stdout, "\n");
     
    return 0;
}

void parseCommandLine(int argc, char *argv[]) {
    int ch;                         /* storage var for getopt info */

    /* just to be sane.. */
    mode = MODE_UPDATE;

    /* loop through each command line var and process it */
    while((ch = getopt(argc, argv, valid_options)) != -1) {
        switch(ch) {
            case CF_STATIC:
                break;

            case OPT_USER: /* Explicitly defined user */
                user_text = strdup(optarg);
                break;

            case 'D':
                snprintf(dbname, 512, "%s", optarg);
                break;

            case 'h': /* show help and exit with 1 */
                mode = MODE_USAGE;
                break;

            case 'V': /* show version information */
                mode = MODE_VERSION;
                break;

            case 'a': /* add yubikey entry to the database */
                mode = MODE_ADD;
                break;

            case 'c': /* prompt for additional passcode (2nd factor */
                entry.flags |= YKDB_TOKEN_ENC_PASSCODE;
                break;

            case 'd': /* delete yubikey entry to the database */
                mode = MODE_DELETE;
                break;
            
            case 'k': /* AES key */
                key_text = strdup(optarg);
                break;

            case 'f': /* Public UID */
                public_uid_text = strdup(optarg);
                break;

            case 'o': /* Yubikey OTP */
                otp = strdup(optarg);
                break;

            case 'p': /* Private UID */
                private_uid_text = strdup(optarg);
                break;
        }   
    }
    
    /* there may be some left over arguments */
    if (optind < argc) {
        /* an explicit declaration overrides this */
        if (user_text == NULL) {
            /* grab the first additional argument as the user name */
            user_text = strdup(argv[optind]);
        }
    }
}

int getPublicUID(void) {
    if (NULL != otp)
        parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (const uint8_t *)otp, NULL);
        
    /* obtain the private_uid if not already defined and store the hash */
    if ( NULL == public_uid_text && public_uid_bin_size <= 0 ) {
        public_uid_text = getInput("Public UID [max 32 hex chars]: ", 32, 0, GETLINE_FLAGS_DEFAULT);
    }

    if ( NULL != public_uid_text && public_uid_bin_size <= 0 ) {
        /* decode the public uid if in hex format */
        if ( ! checkHexString((const uint8_t *)public_uid_text) ) {
            if ( strlen(public_uid_text) > 32 ) {
                printf("Public UID is too long! Max of 32 hex chars allowed.\n");
                return -1;
            }

            public_uid_bin_size = hexDecode(public_uid_bin, (const uint8_t *)public_uid_text, PUBLIC_UID_BYTE_SIZE);
        /* decode the public uid if in modhex format */
        } else if ( ! checkModHexString((const uint8_t *)public_uid_text) ) {
            if ( strlen(public_uid_text) > 32 ) {
                printf("Public UID is too long! Max of 32 modhex chars allowed.\n");
                return -1;
            }

            public_uid_bin_size = modHexDecode(public_uid_bin, (const uint8_t *)public_uid_text, PUBLIC_UID_BYTE_SIZE);
        } else {
            printf("Public UID [%s] must be in hex format!\n", public_uid_text);
            return -1;
        }
    } else if ( public_uid_bin_size <= 0 ) {
        printf("No Public UID specified!\n");
        return -1;
    }

    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
    
    return 0;
}

int addYubikeyEntry(void) {
    uint8_t ticket_enc_key[256];
    uint8_t ticket_enc_hash[32];
    uint8_t i;

    printf("Adding Yubikey entry for %s\n", user_text);
    
    /* obtain and store the AES key if not already defined */
    if (NULL == key_text)
        key_text = getInput("AES key [exactly 32 hex chars]: ", 32, 32, GETLINE_FLAGS_DEFAULT);
    
    if (NULL != key_text) {
        if ( !checkHexString((const uint8_t *)key_text) )
            hexDecode((uint8_t *)&entry.ticket.key, (const uint8_t *)key_text, KEY_BYTE_SIZE);
        else if ( ! checkModHexString((const uint8_t *)key_text) )
            modHexDecode((uint8_t *)&entry.ticket.key, (const uint8_t *)key_text, KEY_BYTE_SIZE);
        else {
            printf("Invalid key specified!\n");
            return -1;
        }
    } else {
        printf("No key specified!\n");
        return -1;
    }

    /* check for an OTP first which will provide public UID and private UID */
    /* with a valid key */
    if ( NULL != otp ) {
        /* decode the OTP */
        if ( parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (const uint8_t *)otp, entry.ticket.key ) != 0 ) {
            printf("Invalid OTP specified!\n");
            return -1;
        }

        /* print public UID */
        if (public_uid_bin_size > 0) {
            printf("Using public UID: ");
            for (i=0; i<public_uid_bin_size; i++)
                printf("%02x ", public_uid_bin[i]);
            printf("\n");
        }

        /* extract the private UID */
        memcpy(private_uid_bin, tkt.private_uid, PRIVATE_UID_BYTE_SIZE);

        /* print private UID */
        private_uid_bin_size = PRIVATE_UID_BYTE_SIZE;
        printf("Using private UID: ");
        for (i=0; i<PRIVATE_UID_BYTE_SIZE; i++)
            printf("%02x ", tkt.private_uid[i]);
        printf("\n");

        /* extract counter information, because we can */
        entry.ticket.last_session = tkt.session_counter;
        entry.ticket.last_timestamp_lo = tkt.timestamp_lo;
        entry.ticket.last_timestamp_hi = tkt.timestamp_hi;
        entry.ticket.last_button = tkt.button_counter;
    }

    /* obtain the private_uid if not already defined and store the hash */
    if ( NULL == private_uid_text && private_uid_bin_size <= 0 )
        private_uid_text = getInput("Private UID [exactly 12 hex chars]: ", 12, 12, GETLINE_FLAGS_DEFAULT);

    if ( NULL != private_uid_text && private_uid_bin_size <= 0 ) {
        if ( ! checkHexString((const uint8_t *)private_uid_text) )
            hexDecode(private_uid_bin, (const uint8_t *)private_uid_text, PRIVATE_UID_BYTE_SIZE);
        else if ( ! checkModHexString((const uint8_t *)private_uid_text) )
            modHexDecode(private_uid_bin, (const uint8_t *)private_uid_text, PRIVATE_UID_BYTE_SIZE);
        else {
            printf("Invalid UID specified!\n");
            return -1;
        }
    } else if ( private_uid_bin_size <= 0 ) {
        printf("No Private UID specified!\n");
        return -1;
    }

    getSHA256(private_uid_bin, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&entry.ticket.private_uid_hash);

    /* encrypt entry as required */
    safeSnprintf((char *)ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ) {
        safeSnprintfAppend((char *)ticket_enc_key, 256, "|", public_uid_bin);
        for(i=0; i<public_uid_bin_size; i++)
            safeSnprintfAppend((char *)ticket_enc_key, 256, "%02x", public_uid_bin[i]);
    }
    
    if ( entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        /* obtain and store the second factor passcode if not already defined */
        passcode_text = getInput("Passcode: ", 256, 0, GETLINE_FLAGS_ECHO_OFF);
        
        if ( NULL != passcode_text ) {
            getSHA256((const uint8_t *)passcode_text, strlen(passcode_text), (uint8_t *)&entry.passcode_hash);
            safeSnprintfAppend((char *)ticket_enc_key, 256, "|%s", passcode_text);
        }
    }
    
    safeSnprintfAppend((char *)ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

#ifdef DEBUG
    printf("Using encryption key: %s\n", ticket_enc_key);
#endif

    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
            entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        getSHA256((const uint8_t *)ticket_enc_key, strlen((const char *)ticket_enc_key), ticket_enc_hash);
        aesEncryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_hash, ticket_enc_hash+16);
    }

    if ( ykdbEntryAdd(handle, &entry) != YKDB_SUCCESS ) {
        printf("Unable to write to the database: %s [%d]\n", YKDB_FILE, ykdb_errno);
        return 1;
    }

#ifdef DEBUG
    /* print the entry */
    ykdbPrintEntry(&entry);
#endif

    return 0;
}

int updateYubikeyEntry(void) {
    uint8_t ticket_enc_key[256];
    uint8_t ticket_enc_hash[32];
    uint8_t i;
    ykdb_entry tmp_entry;

    printf("Updating Yubikey entry for %s\n", user_text);

    if ( ykdbEntryGet(handle, &tmp_entry) != YKDB_SUCCESS )
        return 1;

    /* decrypt entry before updating */
    safeSnprintf((char *)ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

    if ( tmp_entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ) {
        safeSnprintfAppend((char *)ticket_enc_key, 256, "|", public_uid_bin);
        for(i=0; i<public_uid_bin_size; i++)
            safeSnprintfAppend((char *)ticket_enc_key, 256, "%02x", public_uid_bin[i]);
    }
    
    if ( tmp_entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        /* obtain and store the second factor passcode if not already defined */
        passcode_text = getInput("Yubikey passcode: ", 256, 0, GETLINE_FLAGS_ECHO_OFF);
        
        if (passcode_text != NULL) {
            getSHA256((const uint8_t *)passcode_text, strlen((const char *)passcode_text), (uint8_t *)&entry.passcode_hash);
            safeSnprintfAppend((char *)ticket_enc_key, 256, "|%s", passcode_text);
        }
    
        if ( memcmp(tmp_entry.passcode_hash, entry.passcode_hash, 32) )
            return 1;
    }
    
    safeSnprintfAppend((char *)ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

    getSHA256((const uint8_t *)ticket_enc_key, strlen((const char *)ticket_enc_key), ticket_enc_hash);
    aesDecryptCBC((uint8_t *)&tmp_entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);

    return 0;
}

int deleteYubikeyEntry(void) {
    uint8_t ticket_enc_key[256];
    uint8_t ticket_enc_hash[32];
    uint8_t i;
    ykdb_entry tmp_entry;

    printf("Deleting Yubikey entry for %s\n", user_text);

    if ( ykdbEntryGet(handle, &tmp_entry) != YKDB_SUCCESS )
        return 1;

    /* decrypt entry as required */
    safeSnprintf((char *)ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

    if ( tmp_entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ) {
        safeSnprintfAppend((char *)ticket_enc_key, 256, "|", public_uid_bin);
        for(i=0; i<public_uid_bin_size; i++)
            safeSnprintfAppend((char *)ticket_enc_key, 256, "%02x", public_uid_bin[i]);
    }
    
    if ( tmp_entry.flags & YKDB_TOKEN_ENC_PASSCODE ) {
        /* obtain and store the second factor passcode if not already defined */
        passcode_text = getInput("Passcode: ", 256, 0, GETLINE_FLAGS_ECHO_OFF);
        
        if (passcode_text != NULL) {
            getSHA256((const uint8_t *)passcode_text, strlen(passcode_text), (uint8_t *)&entry.passcode_hash);
            safeSnprintfAppend((char *)ticket_enc_key, 256, "|%s", passcode_text);
        }
    
        if ( memcmp(tmp_entry.passcode_hash, entry.passcode_hash, 32) )
            return 1;
    }
    
    safeSnprintfAppend((char *)ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

    getSHA256(ticket_enc_key, strlen((const char *)ticket_enc_key), ticket_enc_hash);
    aesDecryptCBC((uint8_t *)&tmp_entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);

#ifdef DEBUG
    ykdbPrintEntry(&tmp_entry);
#endif

    if ( ykdbEntryDelete(handle) != YKDB_SUCCESS ) {
        printf("Unable to write to the database: %s [%d]\n", YKDB_FILE, ykdb_errno);
        return 1;
    }

    return 0;
}


// Main
int main (int argc, char *argv[]) {
    char *progname = NULL;
    int amroot = 0;
    uint8_t user_exists = 0;
    struct passwd *pw;

    /* save the program name */
    progname = argv[0];

    /* set default values for the entry */
    entry.flags = YKDB_TOKEN_ENC_PUBLIC_UID;
    entry.ticket.last_session = 0x0000;
    entry.ticket.last_timestamp_lo = 0x0000;
    entry.ticket.last_timestamp_hi = 0x00;
    entry.ticket.last_button = 0x00;
    
    parseCommandLine(argc, argv);

    amroot = ( getuid() == 0 );

    /* if no user specified use calling user */
    if (NULL == user_text) {
        /* get passwd structure for current user */
        pw = getpwuid(getuid());

        if (NULL == pw) {
            fprintf(stderr, "Can't determine your user name\n");
            clean();
            exit(EXIT_FAILURE);
        }

        user_text = strdup(pw->pw_name);
    }

    /* show usage when in USAGE mode or no user was provided */
    if (mode == MODE_USAGE || NULL == user_text) {
        showUsage(progname);
        clean();
        exit(EXIT_FAILURE);
    } else if (mode == MODE_VERSION) {
        showVersion("ykpasswd - Yubikey OTP/Passcode Utility");
    }

    /* set additional default values for the entry after parsing */
    getSHA256((const uint8_t *)user_text, strlen(user_text), (uint8_t *)&entry.user_hash);

    /* get passwd structure for desired user */
    pw = getpwnam(user_text);

    if (NULL == pw) {
        fprintf(stderr, "Unknown user: %s\n", user_text);
        clean();
        exit(EXIT_FAILURE);
    }

    /* check if we have privelege to update users information */
    if ( !amroot && pw->pw_uid != getuid() ) {
        fprintf(stderr, "You may not view or modify yubikey information for %s\n", user_text);
        clean();
        exit(EXIT_FAILURE);
    }

    /* get perms */
    setregid( getegid(), -1 );

    /* open the db or create if empty */
    handle = ykdbDatabaseOpen(dbname);
    if (handle == NULL) {
        handle = ykdbDatabaseCreate(dbname);

        if (handle == NULL) {
            printf("Unable to access the database: %s [%d]\n", dbname, ykdb_errno);
            clean();
            exit(EXIT_FAILURE);
        }
    }

    if (mode == MODE_ADD) {
        /* require unique Public UID when adding an already existing user */
        if ( getPublicUID() != 0 ) {
            clean();
            exit(EXIT_FAILURE);
        }

        if ( ykdbEntrySeekOnUserPublicHash(handle, (uint8_t *)&entry.user_hash, (uint8_t *)&entry.public_uid_hash, YKDB_SEEK_START) == YKDB_SUCCESS ) {
            fprintf(stderr, "Entry for user \"%s\" and public UID already exist.\n", user_text);
            clean();
            exit(EXIT_FAILURE);
        }

        if ( addYubikeyEntry() != 0 ) {
            clean();
            exit(EXIT_FAILURE);
        }
    } else if (mode == MODE_UPDATE) {
        /* can't update when one doesn't exist */
        if (!user_exists) {
            fprintf(stderr, "Entry for %s does not exist.\n", user_text);
            clean();
            exit(EXIT_FAILURE);
        }

        if ( updateYubikeyEntry() != 0) {
            clean();
            exit(EXIT_FAILURE);
        }
    } else if (mode == MODE_DELETE) {
        /* can't delete when one doesn't exist */
        if (!user_exists) {
            fprintf(stderr, "Entry for %s does not exist.\n", user_text);
            clean();
            exit(EXIT_FAILURE);
        }

        if ( deleteYubikeyEntry() != 0 ) {
            clean();
            exit(EXIT_FAILURE);
        }
    }
    /* sync to the yubikey */

    /* close the db */
    ykdbDatabaseClose(handle);

    fprintf(stdout, "Completed successfully.\n");

    clean();
    return 0;
}

