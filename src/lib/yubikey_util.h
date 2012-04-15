/*
* YubiKey PAM Utils Module
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

#ifndef	__YK_UTIL_H__
#define	__YK_UTIL_H__

#include <stdint.h>

#include "yubikey_common.h"

#ifdef __BIG_ENDIAN__
    #define ENDIAN_SWAP_16(x) x = ((x) >> 8) | ((x) << 8)
#else
    #define ENDIAN_SWAP_16(x)
#endif

#define SHA256_DIGEST_SIZE (8*sizeof(uint32_t))
#define MODHEX_MAP "cbdefghijklnrtuv"
#define HEX_MAP "0123456789abcdef"
#define CRC_OK_RESIDUE 0xf0b8
#define GETLINE_FLAGS_DEFAULT 0
#define GETLINE_FLAGS_ECHO_OFF 1
#define MAX_FD_NO 10000

/* public API */
int safeSnprintf(char *buf, size_t buf_size, const char *format, ...);
int safeSnprintfAppend(char *buf, size_t buf_size, const char *format, ...);
int safeStrnlen(const char *buf, int buf_size);
char *getInput(const char *prompt, int size, int required, uint8_t flags);
struct passwd *getPWEnt(void);
int _yubi_run_helper_binary(const char *otp_passcode, const char *user, int debug);
int checkHexString(const uint8_t *);
int checkModHexString(const uint8_t *);
int checkOTPCompliance(const uint8_t *, uint32_t);

/* cipher/ routines */
void aesEncryptBlock(uint8_t *, const uint8_t *);
void aesDecryptBlock(uint8_t *, const uint8_t *);
void aesEncryptCBC(uint8_t *, uint32_t, const uint8_t *, const uint8_t *);
void aesDecryptCBC(uint8_t *, uint32_t, const uint8_t *, const uint8_t *);
void getSHA256(const uint8_t *, uint32_t, uint8_t *);
uint16_t getCRC(const uint8_t *, uint32_t);

/* yubikey routines */
uint32_t modHexDecode(uint8_t *, const uint8_t *, uint32_t);
uint32_t modHexEncode(uint8_t *, const uint8_t *, uint32_t);
int parseOTP(yk_ticket *, uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
void printTicket(yk_ticket *);

#endif
