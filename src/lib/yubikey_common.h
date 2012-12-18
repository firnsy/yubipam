/*
* YubiKey PAM Common API
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

/*
 * Original Code adapted from YubiCo
 */

/*
 *    Y K D E F  -  Common Yubikey project header
 *
 *    Date / Rev        / Sign / Remark
 *    06-06-03 / 0.9.0  / J E / Main
 *    06-08-25 / 1.0.0  / J E / Rewritten for final spec
 *    08-06-03 / 1.3.0c	/ J E / Added static OTP feature
 */

#ifndef	__YK_COMMON_H__
#define	__YK_COMMON_H__

#include <stdint.h>

#define YKDB_FILE "/etc/yubikey"

#define YK_SUCCESS 0
#define YK_FAILURE 1
#define YK_PASSCODE 128

// slot entries
#define	SLOT_CONFIG 1
#define	SLOT_NAV 2
#define	SLOT_DATA_SIZE 64

// Activation modifier of sessionUse field (bitfields not uses as they are not portable)
#define	TICKET_ACT_HIDRPT 0x8000  // Ticket generated at activation by keyboard (scroll/num/caps)
#define	TICKET_CTR_MASK 0x7fff    // Mask for useCtr value (except HID flag)

// Configuration structure
#define	PUBLIC_UID_BYTE_SIZE 16   // max byte size of fixed public UID field
#define	KEY_BYTE_SIZE 16          // byte size of AES key
#define	PRIVATE_UID_BYTE_SIZE 6   // byte size of private UID field
#define	ACCESS_CODE_BYTE_SIZE 6   // max byte size of access code to re-program device

// ticket structure
typedef struct _yk_ticket {
    uint8_t private_uid[PRIVATE_UID_BYTE_SIZE];
    uint16_t session_counter;						
    uint16_t timestamp_lo;
    uint8_t timestamp_hi;			
    uint8_t button_counter;
    uint16_t random;
    uint16_t crc;
} yk_ticket;

typedef struct _yk_usb_config {
    uint8_t public_uid[PUBLIC_UID_BYTE_SIZE];	
    uint8_t private_uid[PRIVATE_UID_BYTE_SIZE];	
    uint8_t key[KEY_BYTE_SIZE];			
    // Access code to re-program device
    uint8_t accCode[ACCESS_CODE_BYTE_SIZE];	
    // Number of bytes in fixed field (0 if not used)
    uint8_t public_uid_size;    // fixedSize
    // Program sequence number (ignored at programming - updated by firmware)
    uint8_t pgmSeq;						
    // Ticket configuration flags
    uint8_t tktFlags;						
    // General configuration flags
    uint8_t cfgFlags;						
    // Counter offset value (ignored at programming - updated by firmware)
    uint16_t ctrOffs;						
    // CRC16 value of all fields
    uint16_t crc;							
} CONFIG;

// Ticket flags
#define	TKTFLAG_TAB_FIRST 0x01      // Send TAB before first part
#define	TKTFLAG_APPEND_TAB1 0x02    // Send TAB after first part
#define	TKTFLAG_APPEND_TAB2 0x04    // Send TAB after second part
#define	TKTFLAG_APPEND_DELAY1 0x08  // Add 0.5s delay after first part
#define	TKTFLAG_APPEND_DELAY2 0x10  // Add 0.5s delay after second part
#define	TKTFLAG_APPEND_CR 0x20      // Append CR as final character

// Configuration flags
#define CFGFLAG_SEND_REF 0x01       // Send reference string (0..F) before data
#define	CFGFLAG_TICKET_FIRST 0x02   // Send ticket first (default is fixed part)
#define CFGFLAG_PACING_10MS 0x04    // Add 10ms intra-key pacing
#define CFGFLAG_PACING_20MS 0x08    // Add 20ms intra-key pacing
#define CFGFLAG_ALLOW_HIDTRIG 0x10  // Allow trigger through HID/keyboard
#define CFGFLAG_STATIC_TICKET 0x20  // Static ticket generation

// Navigation
#define	MAX_URL	48

typedef struct _yk_usb_nav {
    uint8_t scancode[MAX_URL];      // Scancode (lower 7 bits)
    uint8_t scanmod[MAX_URL >> 2];  // Modifier fields (packed 2 bits each)
    uint8_t flags;		    // NAVFLAG_xxx flags
    uint8_t filler;	            // Filler byte
    uint16_t crc;		    // CRC16 value of all fields
} NAV;

#define	SCANMOD_SHIFT 0x80          // Highest bit in scancode
#define	SCANMOD_ALT_GR 0x01         // Lowest bit in mod
#define	SCANMOD_WIN 0x02            // WIN key

// Navigation flags
#define	NAVFLAG_INSERT_TRIG 0x01    // Automatic trigger when device is inserted
#define NAVFLAG_APPEND_TKT 0x02     // Append ticket to URL
#define	NAVFLAG_DUAL_KEY_USAGE 0x04 // Dual usage of key: Short = ticket  Long = Navigate

// Status block
typedef struct _yk_usb_status {
    uint8_t versionMajor;           // Firmware version information
    uint8_t versionMinor;
    uint8_t versionBuild;
    uint8_t pgmSeq;                 // Programming sequence number. 0 if no valid configuration
    uint16_t touchLevel;            // Level from touch detector
} STATUS;

#endif /* __YK_COMMON_H__ */

