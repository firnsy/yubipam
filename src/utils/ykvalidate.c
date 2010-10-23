/*
* YubiKey PAM Validate Module
*
* Copyright (C) 2008-2010 Ian Firns		firnsy@securixlive.com
* Copyright (C) 2008-2010 SecurixLive	dev@securixlive.com
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

#include "ykvalidate.h"
#include "libyubipam.h"

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

char	*progname;
int		mode;

char *user = NULL;
char *otp = NULL;

void cleanExit(int);
int parseCommandLine(int, char **);
struct passwd *getPWEnt(void);
void showUsage(char *);
char *getInput(const char *, int, int, uint8_t);
static int _yubi_run_helper_binary(const char *, const char *);

int main(int argc, char *argv[])
{
	int	ret = 0;

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

		if (ret != PAM_SUCCESS)	
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

int parseCommandLine(int argc, char *argv[])
{
    int ch;                         /* storage var for getopt info */
    int option_index = -1;
    int isName = 0;
    int i;

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

/* courtesy myname.c (pam_unix) */
struct passwd *getPWEnt(void)
{
    struct passwd       *pw;
    const char          *cp = getlogin();
    uid_t               ruid = getuid();

    if (cp && *cp && (pw = getpwnam(cp)) && pw->pw_uid == ruid)
        return pw;

	return getpwuid(ruid);
}

char * getInput(const char *prompt, int size, int required, uint8_t flags)
{
    int bytes_read;
    char *answer;
    size_t gl_size = size;

    struct termios old, new;
    int nread;
                               
    /* get terminal attributes and fail if we can't */
    if ( tcgetattr(fileno(stdin), &old) != 0 )
        return NULL;
        
    new = old;

    /*turn echoing off and fail if we can't. */
    if ( flags & GETLINE_FLAGS_ECHO_OFF )
        new.c_lflag &= ~ECHO;

    if ( tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0 )
        return NULL;

    while ( (bytes_read-1) != required )
    {
        fprintf(stdout, "%s", prompt);
        answer = malloc(size + 1);
        bytes_read = getline(&answer, &gl_size, stdin);

        if ( (required <= 0) || (NULL == answer) )
            break;
    }

    if ( NULL != answer )
    {
        if (bytes_read >= size)
            answer[size] = '\0';
        else
            answer[bytes_read-1] = '\0';
    }

    /* restore terminal */
    (void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

    return answer;
}

/*
 * verify the password of a user
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

#define MAX_FD_NO 10000
#define CHKPWD_HELPER "/sbin/yk_chkpwd"

// this code is from Linux-PAM pam_unix support.c
static int _yubi_run_helper_binary(const char *otp_passcode, const char *user)
{
    int					retval;
	int					child;
	int					fds[2];
    void				(*sighandler)(int) = NULL;

    D(("called."));

    /* create a pipe for the password */
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
		/* if the stored password is NULL */
        int				rc = 0;
        int dummy;

		if (otp_passcode != NULL) 	/* send the OTP/passcode to the child */
		{
		    if ( write(fds[1], otp_passcode, strlen(otp_passcode)+1) == -1 )
            {
		        D(("cannot send OTP/passcode to helper"));
                close(fds[1]);
                retval = PAM_AUTH_ERR;
            }
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

