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
**                                                                      **
**      Y U B I K E Y  -  Basic LibUSB programming API for the Yubikey	**
**                                                                      **
**      Copyright 2008 Yubico AB										**
**                                                                      **
**      Date		/ Sig / Rev  / History                              **
**      2008-06-05	/ J E / 0.00 / Main									**
**                                                                      **
*************************************************************************/

#include <stdio.h>
#include <string.h> // memset(), memcpy()
#include <unistd.h>	// sleep()
#include <usb.h>		// Rename to avoid clash with windows USBxxx headers

#include "yubikey_usb.h"
#include "yubikey_util.h"

#define	YUBICO_VID				0x1050
#define	YUBIKEY_PID				0x0010

#define HID_GET_REPORT			0x01
#define HID_SET_REPORT			0x09

#define	FEATURE_RPT_SIZE		8

#define	REPORT_TYPE_FEATURE		0x03

/*************************************************************************
**  function hidSetReport												**
**  Set HID report														**
**                                                                      **
**  int hidSetReport(YUBIKEY yk, int reportType, int reportNumber,		**
**					 char *buffer, int size)							**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey										**
**	"reportType" is HID report type (in, out or feature)				**
**	"reportNumber" is report identifier									**
**	"buffer" is pointer to in buffer									**
**	"size" is size of the buffer										**
**																		**
**	Returns: Nonzero if successful, zero otherwise						**
**                                                                      **
*************************************************************************/
static int hidSetReport(yk_usb_h *yk, int reportType, int reportNumber, char *buffer, int size)
{
	int					ret;
	ret = usb_control_msg(yk,
						  USB_TYPE_CLASS | USB_RECIP_INTERFACE | USB_ENDPOINT_OUT, HID_SET_REPORT,
						  reportType << 8 | reportNumber,
						  0,
						  buffer,
						  size,
						  1000);

	return ret > 0;
}

/*************************************************************************
**  function hidGetReport												**
**  Get HID report														**
**                                                                      **
**  int hidGetReport(YUBIKEY yk, int reportType, int reportNumber,		**
**					 char *buffer, int size)							**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey										**
**	"reportType" is HID report type (in, out or feature)				**
**	"reportNumber" is report identifier									**
**	"buffer" is pointer to in buffer									**
**	"size" is size of the buffer										**
**																		**
**	Returns: Number of bytes read. Zero if failure						**
**                                                                      **
*************************************************************************/

static int hidGetReport(yk_usb_h *yk, int reportType, int reportNumber, char *buffer, int size)
{
	int ret, hr;

	/* claim interface before communicating */
	ret = usb_claim_interface(yk, 0);
	printf("hidGetReport: claiming interface 0 = %d\n", ret);
	if (ret < 0)
	{
		printf("hidGetReport: interface 0 couldn't be claimed\n");
		
		ret = usb_detach_kernel_driver_np(yk, 0);

		printf("hidGetReport: forcing existing driver detatchment = %d\n", ret);
		ret = usb_claim_interface(yk, 0);
		printf("hidGetReport: attempting reclaim = %d\n", ret);

		if (ret < 0)
			return 0;
	}

	hr = usb_control_msg(yk,
						 USB_TYPE_CLASS | USB_RECIP_INTERFACE | USB_ENDPOINT_IN,
						 HID_GET_REPORT,
						 reportType << 8 | reportNumber,
						 0,
						 buffer,
						 size,
						 1000);

	printf("hidGetReport: %d\n", ret);

	ret = usb_release_interface(yk, 0);
	printf("hidGetReport: releasing interface 0 = %d\n", ret);
	if (ret < 0)
	{
		printf("hidGetReport: interface 0 couldn't be released\n");
		return 0;
	}

    return hr > 0;
}

/*************************************************************************
**  function ykInit														**
**  Initiates libUsb and other stuff. Call this one first				**
**                                                                      **
**  void ykInit(void)													**
**                                                                      **
*************************************************************************/

int ykUSBInit(void)
{
	int	ret;

	usb_init();

	ret = usb_find_busses();
	printf("ykInit: find_busses() = %d\n", ret);


	if (ret)
	{
		ret = usb_find_devices();
		printf("ykInit: usb_find_devices() = %d\n", ret);
		return ret;
	}

	return 0;
}

/*************************************************************************
**  function ykOpen														**
**  Opens first Yubikey found for subsequent operations					**
**                                                                      **
**  YUBIKEY ykOpen(void)												**
**                                                                      **
**  Returns: Handle to opened Yubikey									**
**                                                                      **
*************************************************************************/

yk_usb_h *ykUSBOpen(void)
{
	struct usb_bus *bus;
	struct usb_device *dev;
	int	ret;

	// Find first instance of the Yubikey
	for (bus = usb_get_busses(); bus; bus = bus->next)
	{
		for (dev = bus->devices; dev; dev = dev->next)
		{
			printf("ykInit: devices() Vendor=0x%x, Product=0x%x\n",
					dev->descriptor.idVendor,
					dev->descriptor.idProduct);

			if (dev->descriptor.idVendor == YUBICO_VID && dev->descriptor.idProduct == YUBIKEY_PID)
			{
				printf("ykInit: A yubikey device WAS found\n");
				return usb_open(dev);
			}
		}
	}

	printf("ykInit: NO yubikey devices found\n");
	return NULL;
}

/*************************************************************************
**  function ykClose													**
**  Closes open Yubikey handle											**
**                                                                      **
**  void ykClose(void)													**
**                                                                      **
*************************************************************************/

void ykUSBClose(yk_usb_h *yk)
{
	usb_close((usb_dev_handle *) yk);
}

/*************************************************************************
**  function ykGetStatus												**
**  Read the Yubikey status structure									**
**                                                                      **
**  int ykGetStatus(YUBIKEY *yk, STATUS *status, int forceUpdate)		**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey										**
**	"status" is pointer to returned status structure					**
**	"forceUpdate" is set to nonzero to force update of dynamic fields	**
**																		**
**	Returns: Nonzero if successful, zero otherwise						**
**                                                                      **
*************************************************************************/
int ykUSBGetStatus(yk_usb_h *yk, STATUS *status, uint8_t forceUpdate)
{
	unsigned char buf[FEATURE_RPT_SIZE];

	// Read status structure

	memset(buf, 0, sizeof(buf));

	if (!hidGetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE))
	{
		printf("ykGetStatus: Failed to get HID report\n");
		return 0;

	}

	memcpy(status, buf + 1, sizeof(STATUS)); 
	ENDIAN_SWAP_16(status->touchLevel);

	// If force update, force Yubikey to update its dynamic
	// status value(s)

	if (forceUpdate) {
		memset(buf, 0, sizeof(buf));
		buf[FEATURE_RPT_SIZE - 1] = 0x8a;	// Invalid partition = update only
		hidSetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE);
	}

	return 1;
}

/*************************************************************************
**  function ykWriteSlot												**
**  Writes data to Yubikey slot											**
**                                                                      **
**  static int ykWriteSlot(YUBIKEY *yk, unsigned char slot,				**
**						   const void *buf, int bcnt)					**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey										**
**	"slot" is slot number to write to									**
**	"buf" is pointer to write data buffer								**
**	"bcnt" is number of bytes to write									**
**																		**
**	Returns: Nonzero if successful, zero otherwise						**
**                                                                      **
*************************************************************************/

static int ykUSBWriteSlot(yk_usb_h *yk, unsigned char slot, const void *dt, int bcnt)
{
	unsigned char buf[FEATURE_RPT_SIZE], data[SLOT_DATA_SIZE + FEATURE_RPT_SIZE];
	int i, j, pos, part;

	// Insert data and set slot #

	memset(data, 0, sizeof(data));
	memcpy(data, dt, bcnt);
	data[SLOT_DATA_SIZE] = slot;

	// Append slot checksum

	i = getCRC(data, SLOT_DATA_SIZE);
	data[SLOT_DATA_SIZE + 1] = (unsigned char) (i & 0xff);
	data[SLOT_DATA_SIZE + 2] = (unsigned char) (i >> 8);

	// Chop up the data into parts that fits into the payload of a
	// feature report. Set the part number | 0x80 in the end
	// of the feature report. When the Yubikey has processed it,
	// it will clear this byte, signaling that the next part can be sent

	for (pos = 0, part = 0x80; pos < (SLOT_DATA_SIZE + 4); part++) {

		// Ignore parts that are all zeroes except first and last
		// to speed up the transfer
		for (i = j = 0; i < (FEATURE_RPT_SIZE - 1); i++)
			if (buf[i] = data[pos++])
				j = 1;

		if (!j && (part > 0x80) && (pos < SLOT_DATA_SIZE))
			continue;

		buf[i] = part;

		if ( !hidSetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE) )
			return 0;

		// When the last byte in the feature report is cleared by
		// the Yubikey, the next part can be sent
		for (i = 0; i < 50; i++)
		{
			memset(buf, 0, sizeof(buf));
			if ( !hidGetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE) )
				return 0;

			if ( !buf[FEATURE_RPT_SIZE - 1] )
				break;

			sleep(10);
		}

		// If timeout, something has gone wrong
		if (i >= 50)
			return 0;	
	}

	return 1;
}

/*************************************************************************
**  function ykWriteConfig												**
**  Writes key config structure											**
**                                                                      **
**  int ykGetStatus(YUBIKEY *yk, STATUS *status, unsigned char accCode)	**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey										**
**	"cfg" is pointer to configuration structure. NULL to zap			**
**	"accCode" is current program access code. NULL if none				**
**																		**
**	Returns: Nonzero if successful, zero otherwise						**
**                                                                      **
*************************************************************************/

int ykUSBWriteConfig(yk_usb_h *yk, CONFIG *cfg, unsigned char *accCode)
{
	unsigned char buf[sizeof(CONFIG) + ACCESS_CODE_BYTE_SIZE];
	STATUS stat;
	int seq;

	// Get current seqence # from status block
	if (!ykUSBGetStatus(yk, &stat, 0)) return 0;

	seq = stat.pgmSeq;

	// Update checksum and insert config block in buffer if present
	memset(buf, 0, sizeof(buf));

	if (cfg)
	{
		cfg->crc = ~getCRC((unsigned char *) cfg, sizeof(CONFIG) - sizeof(cfg->crc));
		ENDIAN_SWAP_16(cfg->crc);
		memcpy(buf, cfg, sizeof(CONFIG));
	}

	// Append current access code if present
	if (accCode)
		memcpy(buf + sizeof(CONFIG), accCode, ACCESS_CODE_BYTE_SIZE);

	// Write to Yubikey
	if ( !ykUSBWriteSlot(yk, SLOT_CONFIG, buf, sizeof(buf)) )
		return 0;

	// Verify update
	if ( !ykUSBGetStatus(yk, &stat, 0) )
		return 0;

	if (cfg)
		return stat.pgmSeq != seq;

	return stat.pgmSeq == 0;
}
