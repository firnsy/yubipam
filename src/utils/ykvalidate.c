/*
* YubiKey PAM Validate Module
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "ykvalidate.h"
#include "libyubipam.h"

int debug = 0;
int mode;
char *user = NULL;
char *otp = NULL;

static char *valid_options = "hu:dV";

void showUsage(char *program_name) {
    fprintf(stdout, "USAGE: %s [OPTION]... OTP\n", program_name);
    fprintf(stdout, "\n");
    fprintf(stdout, "   -h          Show this information\n");
    fprintf(stdout, "   -u <user>   Apply configuration to <user>\n");
    fprintf(stdout, "   -d          Log debug info to syslog\n");
    fprintf(stdout, "   -V          Show version and exit\n");
    fprintf(stdout, "\n");
}

void clean(void) {
    /* free any and all allocated memory */
    free(user);
    free(otp);
}

void parseCommandLine(int argc, char *argv[]) {
    int ch;    /* storage var for getopt info */

    /* just to be sane.. */
    mode = MODE_VALIDATE;

    /* loop through each command line var and process it */
    while((ch = getopt(argc, argv, valid_options)) != -1) {
        switch(ch) {
            case 'u': /* Explicitly defined user */
                user = strdup(optarg);
                break;

            case 'h': /* show help and exit with 1 */
                mode = MODE_USAGE;
                break;

            case 'd': /* Set debug mode on */
                debug = 1;
                break;

            case 'V': /* show version information */
                mode = MODE_VERSION;
                break;
        }
    }
    
    /* there should be at least one left over argument */
    if (optind < argc) {
        /* an explicit declaration overrides this */
        if (otp == NULL) {
            /* grab the first additional argument as the user name */
            otp = strdup(argv[optind]);
        }
    }
}


// Main
int main(int argc, char *argv[]) {
    char *progname = NULL;
    int ret = 0;

    // OTP 64 bytes + ' ' separator + Passcode 64 bytes + null terminator
    char otp_passcode[130];
    char *passcode = NULL;

    struct passwd *pw;

    progname = argv[0];
    parseCommandLine(argc, argv);

    if (mode & MODE_VALIDATE) {
        if ( NULL == user ) {
            /* get passwd structure for current user */
            pw = getpwuid(getuid());
 
            if ( NULL == pw ) {
                fprintf(stderr, "Can't determine your user name!\n");
                clean();
                exit(YK_FAILURE);
            }
            
            user = strdup(pw->pw_name);
        }
 
        /* get passwd structure for desired user */
        pw = getpwnam(user);
     
        if ( NULL == pw ) {
            fprintf(stderr, "Unknown user: %s\n", user);
            clean();
            exit(YK_FAILURE);
        }
     
        if (otp == NULL) {
            fprintf(stderr, "You must at least provide an OTP!\n\n");
            showUsage(progname);
            clean();
            exit(YK_FAILURE);
        }

        snprintf(otp_passcode, 66, "%s|", otp ? otp:"");
        ret = _yubi_run_helper_binary(otp_passcode, user, debug);

        if (ret == YK_PASSCODE) {
            /* Need passcode */
            passcode = getInput("Yubikey passcode: ", 64, -1, GETLINE_FLAGS_ECHO_OFF);
            printf("\n");
            snprintf(otp_passcode, 130, "%s|%s", otp ? otp:"", passcode ? passcode:"");
            ret = _yubi_run_helper_binary(otp_passcode, user, debug);
        }
        free(passcode);

        printf("%s: ", user);

        if (ret != 0)    
            printf("OTP is INVALID!\n");
        else
            printf("OTP is VALID.\n");
    } else if (mode == MODE_USAGE) {
        showUsage(progname);
    } else if (mode == MODE_VERSION) {
        showVersion("ykvalidate - Yubikey OTP/Passcode Validation Utility");
    }

    clean();
    return 0;
}
