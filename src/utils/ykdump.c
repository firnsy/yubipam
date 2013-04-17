/*
* YubiKey PAM Database Dumping Utility
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

#include "libyubipam.h"
#include "ykdump.h"

uint8_t public_uid_bin[PUBLIC_UID_BYTE_SIZE];
uint8_t public_uid_bin_size = 0;
uint32_t entry_idx;

int mode;
ykdb_entry entry;
ykdb_h *handle = NULL;
yk_ticket tkt;
char dbname[512] = CONFIG_AUTH_DB_DEFAULT;

extern int ykdb_errno;
extern uint32_t hexDecode(uint8_t *dst, const uint8_t *src, uint32_t dst_size);

static char *valid_options = "hD:du:f:i:V";

int showUsage(char *program_name) {
    fprintf(stdout, "USAGE: %s [OPTION]...\n", program_name);
    fprintf(stdout, "\n");
    fprintf(stdout, "   -h          Show this information\n");
    fprintf(stdout, "   -D <path>   Explicitly define the database <path>\n");
    fprintf(stdout, "   -d          Dump entire database\n");
    fprintf(stdout, "   -u <user>   Search based on <user>\n");
    fprintf(stdout, "   -f <uid>    Search based on public <uid>\n");
    fprintf(stdout, "   -i <index>  Search based on <index> value\n");
    fprintf(stdout, "   -V          Show version and exit\n");
    fprintf(stdout, "\n");
     
    return 0;
}

void parseCommandLine(int argc, char *argv[]) {
    int ch;    /* storage var for getopt info */

    /* just to be sane.. */
    mode = 0;

    /* loop through each command line var and process it */
    while((ch = getopt(argc, argv, valid_options)) != -1) {
        switch(ch) {
            case 'D':
                snprintf(dbname, 512, "%s", optarg);
                break;

            case 'd': /* show version information */
                mode = MODE_DUMP_ALL;
                break;

            case 'i':
                entry_idx = atoi(optarg);
                mode |= MODE_SEARCH_INDEX;
                break;

            case 'u': /* Explicitly defined user */
                /* set additional default values for the entry after parsing */
                getSHA256((const uint8_t *)optarg, strlen(optarg), (uint8_t *)&entry.user_hash);

                mode |= MODE_SEARCH_USER;
                break;

            case 'h': /* show help and exit with 1 */
                mode = MODE_USAGE;
                break;

            case 'V': /* show version information */
                mode = MODE_VERSION;
                break;

            case 'f': /* Public UID */
                if ( !checkHexString((const uint8_t *)optarg) ) {
                    public_uid_bin_size = hexDecode(public_uid_bin, (const uint8_t *)optarg, PUBLIC_UID_BYTE_SIZE);
                    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
                    mode |= MODE_SEARCH_PUBLIC;

                } else if ( !checkModHexString((const uint8_t *)optarg, NULL) ) {
                    public_uid_bin_size = modHexDecode(public_uid_bin, (const uint8_t *)optarg, PUBLIC_UID_BYTE_SIZE, NULL);
                    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
                    mode |= MODE_SEARCH_PUBLIC;
                } else {
                    fprintf(stderr, "Ignoring unknown public UID format.\n");
                }
                break;
        }    
    }
    
}


// Main
int main (int argc, char *argv[]) {
    char *progname = NULL;
    int amroot = 0;
    int ret;
    int entry_count;

    /* save the program name */
    progname = argv[0];

    /* set default values for the entry */
    *entry.user_hash = 0;
    *entry.public_uid_hash = 0;
    entry.flags = YKDB_TOKEN_ENC_PUBLIC_UID;
    entry.ticket.last_session = 0x0000;
    entry.ticket.last_timestamp_lo = 0x0000;
    entry.ticket.last_timestamp_hi = 0x00;
    entry.ticket.last_button = 0x00;
    
    amroot = ( getuid() == 0 );

    parseCommandLine(argc, argv);

    /* open the DB if we are actually searching */
    if ( mode & (MODE_SEARCH_USER | MODE_SEARCH_PUBLIC | MODE_SEARCH_INDEX | MODE_DUMP_ALL) ) {
        /* check if we have privelege to update users information */
        if ( !amroot ) {
            fprintf(stderr, "You need root privileges to dump the yubikey database.\n");
            exit(YK_FAILURE);
        }
    
        /* Get perms */
        setregid( getegid(), -1 );

        /* open the db or create if empty */
        handle = ykdbDatabaseOpenReadOnly(dbname);
        if (handle == NULL) {
            printf("Unable to access the database: %s [%d]\n", dbname, ykdb_errno);
            exit(YK_FAILURE);
        }
    }

    entry_count = ykdbDatabaseEntryCountGet(handle);

    if ( entry_count == 0 ) {
        printf("The database is empty.\n");
        free(handle);
        exit(YK_SUCCESS);
    }

    if ( mode & MODE_SEARCH_INDEX ) {
        fprintf(stdout, "Searching on index.\n");

        if ( ykdbEntrySeekOnIndex(handle, entry_idx) == YKDB_SUCCESS )
            if ( ykdbEntryGet(handle, &entry) == YKDB_SUCCESS ) {
                fprintf(stdout, "Index: %d\n", entry_idx);
                ykdbPrintEntry(&entry);
            }
    } else if ( (mode & MODE_SEARCH_USER) && (mode & MODE_SEARCH_PUBLIC) ) {
        fprintf(stdout, "Searching on both user and public UID.\n");

        /* we should only have one entry but loop anyway*/
        while ( (ret=ykdbEntrySeekOnUserPublicHash(handle,
                (uint8_t *)&entry.user_hash,
                (uint8_t *)&entry.public_uid_hash,
                YKDB_SEEK_CURRENT
                )) == YKDB_SUCCESS ) {
            
            if ( ykdbEntryGet(handle, &entry) == YKDB_SUCCESS ) {
                ykdbEntryGetIndex(handle, &entry_idx);
                fprintf(stdout, "Index: %d\n", entry_idx);
                ykdbPrintEntry(&entry);
            } else
                fprintf(stderr, "Unable to read entry. Skipping.\n");

            if ( ykdbEntryNext(handle) != YKDB_SUCCESS )
                break;
        }
    } else if (mode & MODE_SEARCH_USER) {
        fprintf(stdout, "Searching on user only.\n");

        while ( (ret=ykdbEntrySeekOnUserHash(handle, (uint8_t *)&entry.user_hash, YKDB_SEEK_CURRENT)) == YKDB_SUCCESS) {
            if ( ykdbEntryGet(handle, &entry) == YKDB_SUCCESS ) {
                ykdbEntryGetIndex(handle, &entry_idx);
                fprintf(stdout, "Index: %d\n", entry_idx);
                ykdbPrintEntry(&entry);
            } else
                fprintf(stderr, "Unable to read entry. Skipping.\n");

            if ( ykdbEntryNext(handle) != YKDB_SUCCESS )
                break;
        }
    } else if (mode & MODE_SEARCH_PUBLIC) {
        fprintf(stdout, "Searching on public UID only.\n");
        
        while ( (ret=ykdbEntrySeekOnPublicHash(handle, (uint8_t *)&entry.public_uid_hash, YKDB_SEEK_CURRENT)) == YKDB_SUCCESS) {
            if ( ykdbEntryGet(handle, &entry) == YKDB_SUCCESS ) {
                ykdbEntryGetIndex(handle, &entry_idx);
                fprintf(stdout, "Index: %d\n", entry_idx);
                ykdbPrintEntry(&entry);
            } else
                fprintf(stderr, "Unable to read entry. Skipping.\n");

            if ( ykdbEntryNext(handle) != YKDB_SUCCESS )
                break;
        }
    } else if (mode == MODE_DUMP_ALL) {
        fprintf(stdout, "Dumping all entries.\n");

        ret = YKDB_SUCCESS;
        int index = 0;

        while ( ret == YKDB_SUCCESS ) {
            if ( ykdbEntryGet(handle, &entry) == YKDB_SUCCESS ) {
                fprintf(stdout, "Index: %d\n", index);
                ykdbPrintEntry(&entry);
                fprintf(stdout, "\n");
            } else
                fprintf(stderr, "Unable to read entry. Skipping.\n");

            index++;
            ret = ykdbEntryNext(handle);
        }
    } else if (mode == MODE_VERSION) {
        showVersion("ykdump - Yubikey Database Dumping Utility");
    } else {
        showUsage(progname);
        free(handle);
        exit(YK_FAILURE);
    }

    /* close the db */
    ykdbDatabaseClose(handle);

    free(handle);
    exit(YK_SUCCESS);
    return 0;
}

