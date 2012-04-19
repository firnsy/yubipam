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


#ifndef __YK_ERR_H__
#define __YK_ERR_H__

#define YK_ERR_NUM 7

#define YK_ERR_UNKOWN 0
#define YK_ERR_IO 1
#define YK_ERR_LOCK 2
#define YK_ERR_INVALID_DB 3
#define YK_ERR_EMPTY_DB 4
#define YK_ERR_SEEK 5
#define YK_ERR_ARGS 6
#define YK_ERR_UNKNOWN 7

#define YK_ERROR( code, desc ) errstr=desc; sotp_errno = code
#define YK_ERROR_RET( code, desc ) errstr=desc; sotp_errno = code; return code

extern char *errstr;
extern int ykdb_errno;

char *yubikey_error_string(void);

#endif /* __YK_ERR_H__ */

