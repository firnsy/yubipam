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

char *progname;
int mode;

char *user = NULL;
char *otp = NULL;

void cleanExit(int);
void parseCommandLine(int, char **);
void showUsage(char *);
int showVersion(void);

int main(int argc, char *argv[])
{
    int    ret = 0;

    char otp_passcode[128];
    char *passcode = NULL;

    struct passwd *pw;

    progname = argv[0];
    parseCommandLine(argc, argv);

    if (mode & MODE_VALIDATE)
    {
        if ( NULL == user )
        {
            /* get passwd structure for current user */
            pw = getPWEnt();
 
            if ( NULL == pw )
            {
                fprintf(stderr, "Can't determine your user name!\n");
                cleanExit(1);
            }
            
            user = strdup(pw->pw_name);
        }
 
        /* get passwd structure for desired user */
        pw = getpwnam(user);
     
        if ( NULL == pw )
        {
            fprintf(stderr, "Unknown user: %s\n", user);
            cleanExit(1);
        }
     
        if (otp == NULL)
        {
            fprintf(stderr, "You must at least provide an OTP!\n\n");
            showUsage(progname);
            cleanExit(1);
        }

        if ( mode & MODE_PASSCODE )
        {
            passcode = getInput("Yubikey Passcode", 64, 0, GETLINE_FLAGS_DEFAULT);
        }

        snprintf(otp_passcode, 128, "%s|%s", otp ? otp:"", passcode ? passcode:"");
        ret = _yubi_run_helper_binary(otp_passcode, user);

        printf("%s: ", user);

        if (ret != 0)    
            printf("OTP is INVALID!\n");
        else
            printf("OTP is VALID.\n");
    }
    else if (mode == MODE_USAGE)
    {
        showUsage(progname);
    }
    else if (mode == MODE_VERSION)
    {
        showVersion();
    }

    cleanExit(ret);
    return 0;
}

void showUsage(char *program_name)
{
    fprintf(stdout, "USAGE: %s [-u|--user USER] OTP\n", program_name);
    fprintf(stdout, "   -c          Prompt for second factor pass code\n");
    fprintf(stdout, "   -u <user>   Apply configuration to <user>\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Longname options and their corresponding single char version\n");
    fprintf(stdout, "   --user <user>   Same as -u\n");
    fprintf(stdout, "   --help          Same as -?\n");
    fprintf(stdout, "   --version       Same as -V\n");
    fprintf(stdout, "\n");
}

void cleanExit(int mode)
{
    /* free any and all allocated memory */
    free(user);
    free(otp);

    /* exit as required */
    exit(mode);
}

/*
** showUsage
**
** Description:
**   Show program version.
*/
int showVersion(void)
{
    fprintf(stderr, "\n"
                       "ykvalidate - Yubikey OTP/Passcode Validation Utility\n"
                    "Version %s.%s.%s (Build %s)\n"
                    "By the SecurixLive team: http://www.securixlive.com/contact.html\n"
                    "\n", VER_MAJOR, VER_MINOR, VER_REVISION, VER_BUILD); 

    return 0;
}

static char *valid_options = "?u:c:V";

#define LONGOPT_ARG_NONE 0
#define LONGOPT_ARG_REQUIRED 1
#define LONGOPT_ARG_OPTIONAL 2
static struct option long_options[] = {
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
   {"user", LONGOPT_ARG_REQUIRED, NULL, 'u'},
   {"version", LONGOPT_ARG_NONE, NULL, 'V'},
   {0, 0, 0, 0}
};

void parseCommandLine(int argc, char *argv[])
{
    int ch;                         /* storage var for getopt info */
    int option_index = -1;

    /* just to be sane.. */
    mode = MODE_VALIDATE;

    /*
    **  Set this so we know whether to return 1 on invalid input because we
    **  use '?' for help and getopt uses '?' for telling us there was an
    **  invalid option, so we can't use that to tell invalid input. Instead,
    **  we check optopt and it will tell us.
    */
    optopt = 0;

    /* loop through each command line var and process it */
    while((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
    {
        switch(ch)
        {
            case 'u': /* Explicitly defined user */
                user = strdup(optarg);
                break;

            case 'c': /* prompt for passcode */
                mode |= MODE_PASSCODE;
                break;

            case '?': /* show help and exit with 1 */
                mode = MODE_USAGE;
                break;

            case 'V': /* show version information */
                mode = MODE_VERSION;
                break;
        }
    }
    
    /* there should be at least one left over argument */
    if (optind < argc)
    {
        /* an explicit declaration overrides this */
        if (NULL == otp)
        {
            /* grab the first additional argument as the user name */
            otp = strdup(argv[optind]);
        }
    }
}

