/*
* YubiKey PAM Error API
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yubikey_err.h"

char *errstr = NULL;
int yubikey_errno;

char *errno_strings[] = {
	"Unknown error",
	"I/O Error",
	"Locking error",
	"Invalid authentication database",
	"Authentication database contains no entries",
	"Entry seek error",
	"Invalid argument to function"
};
		

/* public API implementation */
char *yubikey_error_string( void ) 
{
	
	char *ret;
	
	/* Some checks */
	if (yubikey_errno > YK_ERR_NUM) 
		return NULL;
	
	/* allocate and format the return string */
	if (errstr)
	{ 
		ret = (char*) malloc( (size_t) strlen(errno_strings[yubikey_errno-1]) + strlen(errstr) + 2 );
		sprintf( ret, "%s:%s", errno_strings[yubikey_errno-1], errstr );
	} 
	else
	{
		ret = strdup( errno_strings[yubikey_errno-1] );
	}

	/* free the error string */
	if (errstr != NULL)
		free( errstr );

	errstr = NULL;

	/* return */
	return ret;
}
