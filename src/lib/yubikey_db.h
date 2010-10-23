/*
* YubiKey DB API
*
* Copyright (C) 2008-2010 SecurixLive	dev@securixlive.com
* Copyright (C) 2008-2010 Ian Firns		firnsy@securixlive.com
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

#ifndef __YK_DB_H__
#define __YK_DB_H__

#include <stdint.h>

#define YKDB_MAGIC			"YKDB"
#define YKDB_MAGIC_SIZE		4
#define YKDB_VERSION		0x01
#define YKDB_KEY_BYTE_SIZE	16

#define YKDB_SUCCESS		0
#define YKDB_ERR_ARGS		1
#define YKDB_ERR_IO			2
#define YKDB_ERR_SEEK		3
#define YKDB_ERR_LOCK		4
#define YKDB_ERR_DB_INV		5
#define YKDB_ERR_DB_EMPTY	6

#define YKDB_TOKEN_ENC_PUBLIC_UID	0x01
#define YKDB_TOKEN_ENC_PASSCODE		0x02
#define YKDB_TOKEN_STATIC			0x04

#define YKDB_SEEK_CURRENT   1
#define YKDB_SEEK_START     2

extern int ykdb_errno;

/* data types */
struct _ykdb_header {
	uint8_t				magic[YKDB_MAGIC_SIZE];
	uint8_t				version;
	uint32_t			entry_count;
} __attribute__((__packed__));
typedef struct _ykdb_header ykdb_header;

struct _ykdb_entry_ticket {
	uint8_t				key[YKDB_KEY_BYTE_SIZE];
	uint8_t				private_uid_hash[32];
	uint16_t			last_session;
	uint8_t				last_timestamp_hi;
	uint16_t			last_timestamp_lo;
	uint8_t				last_button;
	uint8_t				reserved[42];
} __attribute__((__packed__));
typedef struct _ykdb_entry_ticket ykdb_entry_ticket;

struct _ykdb_entry {
	uint8_t				user_hash[32];
	uint8_t				public_uid_hash[32];
	uint8_t				passcode_hash[32];
	uint8_t				flags;
	ykdb_entry_ticket	ticket;
} __attribute__((__packed__));
typedef struct _ykdb_entry ykdb_entry; 

struct _ykdb_handle;
typedef struct _ykdb_handle ykdb_h;

/* database API */
ykdb_h *ykdbDatabaseOpen(const char *);
ykdb_h *ykdbDatabaseOpenReadOnly(const char *);
ykdb_h *ykdbDatabaseCreate(const char *);
int ykdbDatabaseClose(ykdb_h *);

uint32_t ykdbDatabaseEntryCountGet(ykdb_h *);

int ykdbEntryNext(ykdb_h *);
int ykdbEntryPrev(ykdb_h *);
int ykdbEntryGet(ykdb_h *, ykdb_entry *);
int ykdbEntrySeekOnIndex(ykdb_h *, uint32_t);
int ykdbEntrySeekOnUserHash(ykdb_h *, uint8_t *, uint8_t);
int ykdbEntrySeekOnPublicHash(ykdb_h *, uint8_t *, uint8_t);
int ykdbEntrySeekOnUserPublicHash(ykdb_h *, uint8_t *, uint8_t *, uint8_t);
int ykdbEntryGetIndex(ykdb_h *, uint32_t *);
int ykdbEntryAdd(ykdb_h *, ykdb_entry *);
int ykdbEntryAdd2(ykdb_h *, uint8_t *, uint8_t *, uint8_t, ykdb_entry_ticket *);
int ykdbEntryWrite(ykdb_h *, ykdb_entry *);
int ykdHeaderWrite(ykdb_h *);
int ykdbEntryDelete(ykdb_h *);
int ykdbEntrySeekEmpty(ykdb_h *);

void ykdbPrintEntry(ykdb_entry *entry);

#endif /* __YK_DB_H__ */
