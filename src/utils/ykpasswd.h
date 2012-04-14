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

#ifndef __YK_PASSWD_H__
#define __YK_PASSWD_H__

#include "ykversion.h"

#define MODE_VERSION 1
#define MODE_USAGE 2
#define MODE_ADD 3
#define MODE_DELETE 4
#define MODE_UPDATE 5

#define TF_TAB_1 10
#define TF_TAB_2 11
#define TF_TAB_3 12
#define TF_DELAY_1 13
#define TF_DELAY_2 14
#define TF_CR 15
#define CF_SEND_REF 16
#define CF_TICKET_FIRST 17
#define CF_PACING_10 18
#define CF_PACING_20 19
#define CF_STATIC 20

#define OPT_USER 1000

#define GETLINE_FLAGS_DEFAULT 0
#define GETLINE_FLAGS_ECHO_OFF 1

#endif /* __YK_PASSWD_H__*/ 
