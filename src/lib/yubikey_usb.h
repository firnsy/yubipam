/*
* YubiKey USB Programming API
*
* Copyright (C) 2008 Ian Firns		firnsy@securixlive.com
* Copyright (C) 2008 SecurixLive	dev@securixlive.com
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

/*
**		Original Code adapted from YubiCo                                 **
*/

/*************************************************************************
** 	  									                                       **
**      Y U B I K E Y  -  Basic LibUSB programming API for the Yubikey	**
**                                                                      **
**      Copyright 2008 Yubico AB										**
**                                                                      **
**      Date		/ Sig / Rev  / History                              **
**      2008-06-05	/ J E / 0.00 / Main									**
**                                                                      **
**************************************************************************
**
**	For binary compatibility, ykdef structures must be byte-aligned
**	Furthermore - define ENDIAN_SWAP appropriately
*/

#ifndef	__YK_USB_H__
#define	__YK_USB_H__

#include "yubikey_common.h"

typedef void yk_usb_h;

int ykUSBInit(void);
yk_usb_h *ykUSBOpen(void);
void ykUSBClose(yk_usb_h *);
int ykUSBGetStatus(yk_usb_h *, STATUS *, uint8_t);
int ykUSBWriteConfig(yk_usb_h *, CONFIG *, uint8_t *);

#endif	/* __YKUTIL_H__ */

