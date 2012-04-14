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

/*
 * Original Code adapted from YubiCo
 * and
 * A contribution to the open-source movement.
 *  Jean-Luc Cooke <jlcooke@certainkey.com>
 *     CertainKey Inc.
 *     Ottawa Ontario Canada
 *
 *  Created: July 20th, 2001
 *
 */

// reference: http://csrc.nist.gov/encryption/shs/dfips-180-2.pdf

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h> //printf
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "yubikey_common.h"
#include "yubikey_util.h"


// start SHA256 requisites - lookup table, defines, etc
typedef struct _sha256_context {
    uint32_t state[8];
    uint8_t buf[128];
    uint32_t count[2];
} sha256_context;

#define ROR32(a,b) (( ((a) >> ((b) & 31)) | ((a) << (32-((b) & 31))) ))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#define e0(x) (ROR32(x,2) ^ ROR32(x,13) ^ ROR32(x,22))
#define e1(x) (ROR32(x,6) ^ ROR32(x,11) ^ ROR32(x,25))
#define s0(x) (ROR32(x,7) ^ ROR32(x,18) ^ (x >> 3))
#define s1(x) (ROR32(x,17) ^ ROR32(x,19) ^ (x >> 10))

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

const uint32_t sha256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define LOAD_OP(I)\
 {\
    t1  = input[(4*I)  ] & 0xff; t1<<=8;\
    t1 |= input[(4*I)+1] & 0xff; t1<<=8;\
    t1 |= input[(4*I)+2] & 0xff; t1<<=8;\
    t1 |= input[(4*I)+3] & 0xff;\
    W[I] = t1;\
 }

#define BLEND_OP(I)\
    W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];

const uint8_t sha256_padding[128] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// end SHA256 requisites

// start AES requisites - lookup table, defines, etc
#define AES_ROUNDS 10
#define AES_BLOCK_SIZE 16

static const unsigned char rcon[] = {
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

static const unsigned char sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char inv_sbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

uint8_t xtime(unsigned char b) {
    return (b & 0x80) ? ((b << 1) ^ 0x1b) : (b << 1); 
}
// end AES requisites


/*
 * checkHexString
 *
 * Description:
 *   Identifies whether a string is a valid hex string.
 *
 * Arguments:
 *   const uint8_t *src            source containing hex characters
 *
 * Return
 *   0 if source is a hex string, non-zero otherwise.
 */
int checkHexString(const uint8_t *src) {
    char trans[] = HEX_MAP;
    uint32_t src_size = strlen((const char *)src);
    uint32_t i;
 
    for(i=0; i<src_size; i++, src++) {
        if ( strchr(trans, tolower(*src)) == NULL )
            return 1;
    }
 
    return 0;
}


/*
 * checkModHexString
 *
 * Description:
 *   Identifies whether a string is a valid modhex string.
 *
 * Arguments:
 *   const uint8_t *src            source containing modhex characters
 *
 * Return
 *   0 if source is a modhex string, non-zero otherwise.
 */
int checkModHexString(const uint8_t *src) {
    char trans[] = MODHEX_MAP;
    uint32_t src_size = strlen((const char *)src);
    uint32_t i;
 
    for(i=0; i<src_size; i++, src++) {
        if ( strchr(trans, tolower(*src)) == NULL )
            return 1;
    }
 
    return 0;
}


/*
 * checkOTPCompliance
 *
 * Description:
 *   Identifies whether the string is compliant with the length and character
 * set.
 *
 * Arguments:
 *   const uint8_t *otp            source containing modhex characters
 *   uint8_t min_pub_uid_len      minimum length of the public_uid (fixed portion)
 *
 * Return
 *   0 if source is compliant, non-zero otherwise.
 */
int checkOTPCompliance(const uint8_t *otp, uint32_t min_pub_uid_len) {
    uint32_t otp_size;
    
    /* check if OTP exists */
    if ( otp == NULL )
        return -1;

    otp_size = strlen((const char *)otp);

    /* check length */
    if ( otp_size < (min_pub_uid_len + 32) )
        return -2;

    /* check modhex character set */
    if ( checkModHexString(otp) )
        return -3;

    return 0;
}

/*
 * hexDecode
 *
 * Description:
 *   Decodeds a hex string into binary. Due to a hex character only
 * representing 4 bits of information, the source should be twice as long as
 * the desired output size.
 *
 * Arguments:
 *   uint8_t *dst                destination of decoded binary information
 *   const uint8_t *src            source containing hex characters
 *   uint32_t dst_size            number of bytes to read into destination buffer
 *
 * Return
 *   Number of modhex characters processed
 */
uint32_t hexDecode(uint8_t *dst, const uint8_t *src, uint32_t dst_size) {
    static const char trans[] = HEX_MAP;
    uint8_t b;
    uint32_t i, processed = 0;
    uint32_t src_size = strlen((const char *)src);
    char *p1;

    /* truncate source if destination is too short */
    if ((dst_size << 1) < src_size)
        src_size = dst_size << 1;

    for (i = 0; i < src_size; i++, src++) {
        /* translate the modhex character, set to 0 if not found */
        if ( (p1 = strchr(trans, tolower(*src))) )
            b = (uint8_t) (p1 - trans);
        else
            b = 0;

        if (i % 2) {
            *dst = (*dst << 4) | b;
            dst++;
            processed++;
        } else
            *dst = b;
    }

    return processed;
}


/*
 * modHexDecode
 *
 * Description:
 *   Decodeds a modhex string into binary. Due to a modhex character only
 * representing 4 bits of information, the source should be twice as long as
 * the desired output size.
 *
 * Arguments:
 *   uint8_t *dst                destination of decoded binary information
 *   const uint8_t *src            source containing modhex characters
 *   uint32_t dst_size            number of bytes to read into destination buffer
 *
 * Return
 *   Number of modhex characters processed
 */
uint32_t modHexDecode(uint8_t *dst, const uint8_t *src, uint32_t dst_size) {
    static const char trans[] = MODHEX_MAP;
    uint8_t b;
    uint32_t i, processed = 0;
    uint32_t src_size = strlen((const char *)src);
    char *p1;

    /* truncate source if destination is too short */
    if ((dst_size << 1) < src_size)
        src_size = dst_size << 1;

    for (i = 0; i < src_size; i++, src++) {
        /* translate the modhex character, set to 0 if not found */
        if ( (p1 = strchr(trans, tolower(*src))) )
            b = (uint8_t) (p1 - trans);
        else
            b = 0;

        if (i % 2) {
            *dst = (*dst << 4) | b;
            dst++;
            processed++;
        } else
            *dst = b;
    }

    return processed;
}


/*
 * aesEncryptCBC
 *
 * Description:
 *   CBC Encryption of any data size.
 *
 * Arguments:
 *   uint8_t * data                data to encrypt
 *   uint32_t data_zise            length of data to encrypt
 *   const uint8_t *key            encryption key
 *   const uint8_t *iv            IV for first block
 */
void aesEncryptCBC(uint8_t *data, uint32_t data_size, const uint8_t *key, const uint8_t *iv) {
    const uint8_t *ivec = iv;
    uint32_t i;

    while (data_size >= AES_BLOCK_SIZE) {
        for(i=0; i<AES_BLOCK_SIZE; ++i)
            data[i] ^= ivec[i];

        aesEncryptBlock(data, key);
        ivec = data;
        data_size -= AES_BLOCK_SIZE;
        data += AES_BLOCK_SIZE;
    }

    if (data_size) {
        for(i=0; i<data_size; ++i)    
            data[i] ^= ivec[i];

        for(i=data_size; i<AES_BLOCK_SIZE; ++i)
            data[i] = ivec[i];

        aesEncryptBlock(data, key);
    }
}

/*
 * aesDecryptCBC
 *
 * Description:
 *   CBC Decryption of any data size.
 *
 * Arguments:
 *   uint8_t * data                data to decrypt
 *   uint32_t data_zise            length of data to decrypt
 *   const uint8_t *key            decryption key
 *   const uint8_t *iv            IV for first block
 */
void aesDecryptCBC(uint8_t *data, uint32_t data_size, const uint8_t *key, const uint8_t *iv) {
    uint8_t ivec[AES_BLOCK_SIZE];
    uint8_t iv_next[AES_BLOCK_SIZE];
    uint32_t i;

    memcpy(ivec, iv, AES_BLOCK_SIZE);
    while (data_size >= AES_BLOCK_SIZE) {
        memcpy(iv_next, data, AES_BLOCK_SIZE);
        aesDecryptBlock(data, key);

        for(i=0; i<AES_BLOCK_SIZE; ++i)
            data[i] ^= ivec[i];

        memcpy(ivec, iv_next, AES_BLOCK_SIZE);
        data_size -= AES_BLOCK_SIZE;
        data += AES_BLOCK_SIZE;
    }

    if (data_size) {
        memcpy(iv_next, data, AES_BLOCK_SIZE);
        aesDecryptBlock(data,key);

        for(i=0; i<data_size; ++i)
            data[i] ^= ivec[i];

        for(i=data_size; i<AES_BLOCK_SIZE; ++i)
            data[i] = iv_next[i];
    }
}

/*
 * aesEncryptBlock
 *
 * Description:
 *   Encrypts a single 128bit block with AES.
 *
 * Arguments:
 *   unsigned char *block      block buffer that contains the data to be
 *                             encrypted (ie. plain in, cipher out);
 *   const unsigned char *key  128-bit key to use for encryption
 */
void aesEncryptBlock(uint8_t *block, const uint8_t *key) {
    uint8_t i, j, k, tmp, round_key[0x10];

    memcpy(round_key, key, sizeof(round_key));

    for (i = 0; i < 16; i++)
        block[i] ^= key[i];

    for (i = 0; i < AES_ROUNDS; i++) {
        // byte_sub_shift_row(block);
        block[0] = sbox[block[0]];
        block[4] = sbox[block[4]];
        block[8] = sbox[block[8]];
        block[12] = sbox[block[12]];

        tmp = block[1];
        block[1] = sbox[block[5]];
        block[5] = sbox[block[9]];
        block[9] = sbox[block[13]];
        block[13] = sbox[tmp];

        tmp = block[2];
        block[2] = sbox[block[10]];
        block[10] = sbox[tmp];
        tmp = block[6];
        block[6] = sbox[block[14]];
        block[14] = sbox[tmp];

        tmp = block[15];
        block[15] = sbox[block[11]];
        block[11] = sbox[block[7]];
        block[7] = sbox[block[3]];
        block[3] = sbox[tmp];

        if (i != (AES_ROUNDS - 1)) {
            // mix_column(block);
            for (k = 0; k < 16; k += 4) {
                j = block[k] ^ block[k + 1];                
                tmp = j ^ block[k + 2] ^ block[k + 3];
    
                j = xtime(j);

                block[k] ^= (j ^ tmp);

                j = block[k + 1] ^ block[k + 2];
                j = xtime(j);

                block[k + 1] ^= (j ^ tmp);

                j = block[k + 2] ^ block[k + 3];
                j = xtime(j);

                block[k + 2] ^= (j ^ tmp);    
                block[k + 3] = block[k] ^ block[k + 1] ^ block[k + 2] ^ tmp;
            }
        }

        round_key[0] ^= rcon[i];
        
        round_key[0] ^= sbox[round_key[13]];
        round_key[1] ^= sbox[round_key[14]];
        round_key[2] ^= sbox[round_key[15]];
        round_key[3] ^= sbox[round_key[12]];

        for (k = 4; k < 16; k++)
            round_key[k] ^= round_key[k - 4];

        // add_round_key(block, round_key);
        for (j = 0; j < 16; j++)
            block[j] ^= round_key[j];
    }
}

/*
 * aesDecryptBlock
 *
 * Description:
 *   Decrypts a single 128bit block with AES.
 *
 * Arguments:
 *   unsigned char *block      block buffer that contains the data to be
 *                            decrypted (ie. cipher in, plain out);
 *   const unsigned char *key  128-bit key to use for decryption
 */
void aesDecryptBlock(uint8_t *block, const uint8_t *key) {
    uint8_t i, j, round_key[0x10];
    uint8_t a02x, a13x;
    uint8_t a02xx, a13xx;
    uint8_t k1, k2;

    memcpy(round_key, key, sizeof(round_key));
    for (i = 0; i < AES_ROUNDS; i++) {
        round_key[0] ^= rcon[i];

        round_key[0] ^= sbox[round_key[13]];
        round_key[1] ^= sbox[round_key[14]];
        round_key[2] ^= sbox[round_key[15]];
        round_key[3] ^= sbox[round_key[12]];

        for (j = 4; j < 16; j++)
            round_key[j] ^= round_key[j - 4];    
    }

    for (i = 0; i < 0x10; i++)
        block[i] ^= round_key[i];

    for (i = 1; i <= AES_ROUNDS; i++) {
        // inv_byte_sub_shift_row();
        block[0] = inv_sbox[block[0]];
        block[4] = inv_sbox[block[4]];
        block[8] = inv_sbox[block[8]];
        block[12] = inv_sbox[block[12]];

        j = block[13];
        block[13] = inv_sbox[block[9]];
        block[9] = inv_sbox[block[5]];
        block[5] = inv_sbox[block[1]];
        block[1] = inv_sbox[j];

        j = block[2];
        block[2] = inv_sbox[block[10]];
        block[10] = inv_sbox[j];
        j = block[6];
        block[6] = inv_sbox[block[14]];
        block[14] = inv_sbox[j];

        j = block[3];
        block[3] = inv_sbox[block[7]];
        block[7] = inv_sbox[block[11]];
        block[11] = inv_sbox[block[15]];
        block[15] = inv_sbox[j];

        // get_inv_round_key(i);
        for (j = 15; j > 3; j--)
            round_key[j] ^= round_key[j - 4];

        round_key[0] ^= (rcon[AES_ROUNDS - i] ^ sbox[round_key[13]]);

        round_key[1] ^= sbox[round_key[14]];
        round_key[2] ^= sbox[round_key[15]];
        round_key[3] ^= sbox[round_key[12]];

        for (j = 0; j < 16; j++)
            block[j] ^= round_key[j];

        if (i != AES_ROUNDS) {
            // inv_mix_column();
            for (j = 0; j < 16; j += 4) {
                k1 = block[j] ^ block[j + 2];
                a02x = xtime(k1);
                k2 = block[j + 1] ^ block[j + 3];
                a13x = xtime(k2);
                
                k1 ^= (k2 ^ xtime(block[j + 1] ^ block[j + 2]));
                k2 = k1;

                a02xx = xtime(a02x);
                a13xx = xtime(a13x);

                k1 ^= (xtime(a02xx ^ a13xx) ^ a02xx);
                k2 ^= (xtime(a02xx ^ a13xx) ^ a13xx);

                block[j] ^= (k1 ^ a02x);
                block[j + 1] ^= k2;
                block[j + 2] ^= (k1 ^ a13x);
                block[j + 3] ^= (k2 ^ a02x ^ a13x);
            }
        }
    }
}

/*
 *  function getCRC
 *  Calculate ISO13239 checksum of buffer
 *
 *    unsigned short getCRC(const unsigned char *buf, int bcnt)
 *
 *  Where:
 *    "buf" is pointer to buffer
 *    "bcnt" is size of the buffer
 *
 *    Returns: ISO13239 checksum
 *
 */

/*
 * getCRC
 *
 * Description:
 *   Calculates the ISO 13239 16 bit checksum of data.
 *
 * Arguments:
 *   const uint8_t *data       pointer to data buffer
 *   uint32_t size             size of the data bufffer to calculate over
 *
 * Returns:
 *   16 bit ISO 13239 checksum.
 */
uint16_t getCRC(const uint8_t *data, uint32_t size) {
    uint16_t crc = 0xffff;
    uint8_t i;

    while (size--) {
        crc ^= *data++;

        for (i = 0; i < 8; i++) 
            crc = (crc & 1) ? ((crc >> 1) ^ 0x8408) : (crc >> 1);
    }

    return crc;
}

/*
 * parseOTP
 *
 * Description:
 *   Decodeds a Yubikey One Time Pad (OTP) in modhex format. It expects at
 * least 32 modhex characters (ie 128 bits) of information which is the token
 * in it's encrypted format. Additional prepended data is assumed to be the
 * public UID portion of the token.
 *
 * Arguments:
 *   yk_ticket *tkt                destination of parsed ticket information
 *   uint8_t *public_uid        destination of public UID if present
 *   uint8_t *public_uid_size   byte size of the public UID
 *   const uint8_t *otp            source OTP in modhex format (>=32 chars)
 *   const uint8_t *otp            AES decryptino key in hex format (16 bytes)
 *
 * Returns:
 *   Return 0 on success, non zero otherwise.
 */
int parseOTP(yk_ticket *tkt, uint8_t *public_uid, uint8_t *public_uid_size, const uint8_t *otp, const uint8_t *key) {
    uint8_t otp_bin[PUBLIC_UID_BYTE_SIZE + sizeof(yk_ticket)];
    uint32_t otp_bin_size;
    uint16_t crc;

    /* convert from either modhex or hex */
    if ( !checkHexString(otp) ) {
        if ((otp_bin_size = hexDecode(otp_bin, otp, sizeof(otp_bin))) < sizeof(yk_ticket))
            return 1;
    } else if ( !checkModHexString(otp) ) {
        if ((otp_bin_size = modHexDecode(otp_bin, otp, sizeof(otp_bin))) < sizeof(yk_ticket))
            return 1;
    } else {
        return 1;
    }

    /* must be at least the size of a yk_ticket structure */
    if (otp_bin_size < sizeof(yk_ticket))
        return 1;

    /* ticket is located in the last 16 bytes */
    memcpy(tkt, otp_bin + otp_bin_size - sizeof(yk_ticket), sizeof(yk_ticket));

    /* grab the public uid (if present) */
    *public_uid_size = (uint8_t) (otp_bin_size - sizeof(yk_ticket));

    /* limit public uid to maximum allowable by a Yubikey */
    if ( *public_uid_size > PUBLIC_UID_BYTE_SIZE )
        *public_uid_size = PUBLIC_UID_BYTE_SIZE;

    /* store the public uid if exists */
    if (*public_uid_size > 0)
        memcpy(public_uid, otp_bin, *public_uid_size);
    else
        *public_uid_size = 0;

    /* decrypt the single block (ie. 128bit) ticket */
    if (key == NULL)
        return 1;

    aesDecryptBlock((uint8_t *) tkt, key);

    /* calculate CRC of the ticket */
    crc = getCRC((uint8_t *) tkt, sizeof(yk_ticket));

    /* ticket is generated in little endian */
    ENDIAN_SWAP_16(crc);

    if (crc != CRC_OK_RESIDUE)
        return 1;

    // Shape up little-endian fields (if applicable)
    ENDIAN_SWAP_16(tkt->random);
    ENDIAN_SWAP_16(tkt->timestamp_lo);
    ENDIAN_SWAP_16(tkt->button_counter);

    return 0;
}

/*
 * sha256_xform
 *
 * Description:
 *   Perform a 256bit transform on the input block by placing 8 bit words into
 * 32 bit words.
 *
 * Arguments:
 *   uint32_t *state            destination for 32 bit words after transform
 *   const uint8_t *input        source of 8 bit words
 */
void sha256_xform(uint32_t *state, const uint8_t *input) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t W[64];

    int i;
    
    /* load the input */
    for (i=0; i<16; i++)
        LOAD_OP(i);

    /* now blend */
    for (i=16; i<64; i++)
        BLEND_OP(i);

    /* load the state into our registers */
    a=state[0];  b=state[1];  c=state[2];  d=state[3];
    e=state[4];  f=state[5];  g=state[6];  h=state[7];

    /* now blend */
    for (i=0; i<64; i++) {
        t1 = h + e1(e) + Ch(e,f,g) + sha256_K[i] + W[i];
        t2 = e0(a) + Maj(a,b,c);
        h = g;   g = f;   f = e;   e = d + t1;
        d = c;   c = b;   b = a;   a = t1 + t2;
    }

    state[0]+=a;   state[1]+=b;   state[2]+=c;   state[3]+=d;
    state[4]+=e;   state[5]+=f;   state[6]+=g;   state[7]+=h;
}

/*
 * sha256_init
 *
 * Description:
 *   Initialises the context prior to generating a SHA256 hash.
 *
 * Arguments:
 *   sha256_context *C            context structure used during hash generation
 */
void sha256_init(sha256_context *C) {
    C->state[0] = H0;
    C->state[1] = H1;
    C->state[2] = H2;
    C->state[3] = H3;
    C->state[4] = H4;
    C->state[5] = H5;
    C->state[6] = H6;
    C->state[7] = H7;
    C->count[0] = C->count[1] = 0;

    memset(C->buf, 0, 128);
}

/*
 * sha256_update
 *
 * Description:
 *   Updates the context with the stream/block data being passed.
 *
 * Arguments:
 *   sha256_context *C            context structure used during hash generation
 *   const uint8_t *data        input block/stream data to hash
 *   uint32_t size                size of data to process
 */
void sha256_update(sha256_context *C, const uint8_t *data, uint32_t size) {
    uint32_t i, index, chunk_size;

    /* calculate number of bytes mod 128 */
    index = (uint32_t)((C->count[0] >> 3) & 0x3f);

    /* update number of bits */
    if ((C->count[0] += (size << 3)) < (size << 3)) {
        C->count[1]++;
        C->count[1] += (size >> 29);
    }

    chunk_size = 64 - index;

    /* transform in chunks as required */
    if (size >= chunk_size) {
        memcpy((uint8_t *)&C->buf[index], data, chunk_size);
        sha256_xform(C->state, C->buf);

        for (i=chunk_size; i+63<size; i+=64)
            sha256_xform(C->state, &data[i]);

        index = 0;
    } else {
        i = 0;
    }

    /* buffer remaining input */
    memcpy((uint8_t *)&C->buf[index], (uint8_t *)&data[i], size-i);
}

/*
 * sha256_final
 *
 * Description:
 *   Finalies the context and produces the final SHA256 digest.
 *
 * Arguments:
 *   uint8_t *digest            pointer to final hash digest
 *   sha256_context *C            context structure used during hash generation
 */
void sha256_final(uint8_t *digest, sha256_context *C) {
    uint8_t bits[8];
    uint32_t index, pad_size, t;
    uint32_t i, j;

    /* save number of bits */
    t = C->count[0];
    bits[7] = t; t>>=8;
    bits[6] = t; t>>=8;
    bits[5] = t; t>>=8;
    bits[4] = t; t>>=8;
    t = C->count[1];
    bits[3] = t; t>>=8;
    bits[2] = t; t>>=8;
    bits[1] = t; t>>=8;
    bits[0] = t; t>>=8;

    /* pad out to 56 mod 64. */
    index = (C->count[0] >> 3) & 0x3f;
    pad_size = (index < 56) ? (56 - index) : ((64+56) - index);
    sha256_update(C, (uint8_t *)sha256_padding, pad_size);

    /* append length (before padding) */
    sha256_update(C, bits, 8);

    /* store state in digest */
    for (i=j=0; i<8; i++, j+=4) {
        t = C->state[i];
        digest[j+3] = t; t>>=8;
        digest[j+2] = t; t>>=8;
        digest[j+1] = t; t>>=8;
        digest[j  ] = t;
    }

    /* zeroize sensitive information. */
    memset(C, 0, sizeof(sha256_context));
}

/*
 * getSHA256
 *
 * Description:
 *   Produces a SHA256 hash based on teh input data. Wraps the pervious *init,
 * *update and *final functions.
 *
 * Arguments:
 *   const uint8_t *data        input block/stream data to hash
 *   uint32_t size                size of data to process
 *   uint8_t *digest            pointer to final hash digest
 */
void getSHA256(const uint8_t *data, uint32_t size, uint8_t *digest) {
    sha256_context        context;

    if (size <= 0)
        return;

    sha256_init(&context);
    sha256_update(&context, data, size);
    sha256_final(digest, &context);
}

void printTicket(yk_ticket *tkt) {
    int i;
    
    printf("ticket {\n");
    printf("  private uid      = ");
    for (i = 0; i<PRIVATE_UID_BYTE_SIZE; i++)
        printf("%02x ", tkt->private_uid[i]);
    printf("[%u]\n", PRIVATE_UID_BYTE_SIZE);
    printf("  session counter  = 0x%04x (%u)\n", tkt->session_counter, tkt->session_counter); 
    printf("  timestamp (low)  = 0x%04x (%u)\n", tkt->timestamp_lo, tkt->timestamp_lo);
    printf("  timestamp (high) = 0x%02x (%u)\n", tkt->timestamp_hi, tkt->timestamp_hi);
    printf("  button counter   = 0x%02x (%u)\n", tkt->button_counter, tkt->button_counter);
    printf("  pseudo-random    = 0x%04x (%u)\n", tkt->random, tkt->random);
    printf("  crc              = 0x%04x (%u)\n", tkt->crc, tkt->crc);
    printf("}\n");
}

// Guaranteed to be '\0' terminated even if truncation occurs.
int safeSnprintf(char *buf, size_t buf_size, const char *format, ...) {
    va_list ap;
    int ret;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return -1;

    /* zero first byte in case an error occurs with
     * vsnprintf, so buffer is null terminated with
     * zero length */
    buf[0] = '\0';
    buf[buf_size - 1] = '\0';

    va_start(ap, format);
    ret = vsnprintf(buf, buf_size, format, ap);
    va_end(ap);

    if (ret < 0)
        return -1;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size) {
        /* result was truncated */
        buf[buf_size - 1] = '\0';
        return -2;
    }

    return 0;
}

/* Appends to a given string
   Guaranteed to be '\0' terminated even if truncation occurs. */
int safeSnprintfAppend(char *buf, size_t buf_size, const char *format, ...) {
    int str_len;
    int ret;
    va_list ap;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return -1;

    str_len = safeStrnlen(buf, buf_size);

    /* since we've already checked buf and buf_size an error
     * indicates no null termination, so just start at
     * beginning of buffer */
    if (str_len == -1) {
        buf[0] = '\0';
        str_len = 0;
    }

    buf[buf_size - 1] = '\0';
    va_start(ap, format);
    ret = vsnprintf(buf + str_len, buf_size - (size_t)str_len, format, ap);
    va_end(ap);

    if (ret < 0)
        return -1;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size) {
        /* truncation occured */
        buf[buf_size - 1] = '\0';
        return -2;
    }

    return 0;
}

int safeStrnlen(const char *buf, int buf_size) {
    int i = 0;
    
    if (buf == NULL || buf_size <= 0)
        return -1;

    for (i = 0; i < buf_size; i++) {
        if (buf[i] == '\0')
            break;
    }
                      
    if (i == buf_size)
        return -1;
     
    return i;
}

int _getline(char *buf, size_t buf_size) {
    int i;
    int c = 0;

    for (i = 0; i < buf_size -1 && (c = getc(stdin)) != EOF && c != '\n'; ++i)
        buf[i]= c;

    if (c == '\n') {
        buf[i] = c;
        i++;
    }
    buf[i] = '\0';

    return i;
}

char *getInput(const char *prompt, int size, int required, uint8_t flags) {
    int bytes_read = 0;
    char *answer = NULL;
    size_t gl_size = size;

    struct termios old, new;
                               
    /* get terminal attributes and fail if we can't */
    if ( tcgetattr(fileno(stdin), &old) != 0 )
        return NULL;
        
    new = old;

    /*turn echoing off and fail if we can't. */
    if ( flags & GETLINE_FLAGS_ECHO_OFF )
        new.c_lflag &= ~ECHO;

    if ( tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0 )
        return NULL;

    while ( (bytes_read-1) != required ) {
        fprintf(stdout, "%s", prompt);
        answer = malloc(size + 1);
        bytes_read = _getline(answer, gl_size);

        if ( (required <= 0) || (NULL == answer) )
            break;
    }

    if ( NULL != answer ) {
        if (bytes_read >= size)
            answer[size] = '\0';
        else
            answer[bytes_read-1] = '\0';
    }

    /* restore terminal */
    (void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

    return answer;
}

struct passwd *getPWEnt(void) {
    struct passwd *pw;
    const char *cp = getlogin();
    uid_t ruid = getuid();

    if (cp && *cp && (pw = getpwnam(cp)) && pw->pw_uid == ruid)
        return pw;

    return getpwuid(ruid);
}

// verify the OTP/passcode of a user
int _yubi_run_helper_binary(const char *otp_passcode, const char *user) {
    int retval;
    int child;
    int fds[2];
    void (*sighandler)(int) = NULL;

    D((LOG_DEBUG, "called."));

    // create a pipe for the OTP/passcode
    if (pipe(fds) != 0) {
        D((LOG_DEBUG, "could not make pipe"));
        return -1;
    }

    sighandler = signal(SIGCHLD, SIG_DFL);

    // fork
    child = fork();
    if (child == 0) {
        int i = 0;
        struct rlimit rlim;
        static char *envp[] = { NULL };
        char *args[] = { NULL, NULL, NULL, NULL };

        /* reopen stdin as pipe */
        dup2(fds[0], STDIN_FILENO);
       
        if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
            if (rlim.rlim_max >= MAX_FD_NO)
                rlim.rlim_max = MAX_FD_NO;

            for (i=0; i<(int)rlim.rlim_max; i++) {
                if (i != STDIN_FILENO)
                    close(i);
            }
        }
       
        if (geteuid() == 0) {
            /* must set the real uid to 0 so the helper will not error
             * out if pam is called from setuid binary (su, sudo...) */
            setuid(0);
        }
       
        /* exec binary helper */
        args[0] = strdup(CHKPWD_HELPER);
        args[1] = strdup(user);
       
        execve(CHKPWD_HELPER, args, envp);
       
        /* should not get here: exit with error */
        syslog(LOG_ERR, "helper binary is not available");
        exit(EXIT_FAILURE);
    } else if (child > 0) {
        /* wait for child
         * if the stored OTP/passcode is NULL */
        int rc = 0;

        if (otp_passcode != NULL) { /* send the OTP/passcode to the child */
            if ( write(fds[1], otp_passcode, strlen(otp_passcode)+1) == -1 ) {
                D((LOG_DEBUG, "cannot send OTP/passcode to helper"));
                close(fds[1]);
                retval = -1;
            }
            otp_passcode = NULL;
        } else {
            if ( write(fds[1], "", 1) == -1 ) { /* blank OTP/passcode */
                D((LOG_DEBUG, "cannot send OTP/passcode to helper"));
                close(fds[1]);
                retval = -1;
            }
        }

        close(fds[0]); /* close here to avoid possible SIGPIPE above */
        close(fds[1]);

        rc = waitpid(child, &retval, 0); /* wait for helper to complete */

        if (rc < 0) {
            syslog(LOG_ERR, "%s: yk_chkpwd waitpid returned %d: %m", __FUNCTION__, rc);
            retval = -1;
        } else {
            retval = WEXITSTATUS(retval);
        }
    } else {
        D((LOG_DEBUG, "fork failed"));
        close(fds[0]);
        close(fds[1]);
        retval = -1;
    }

    if (sighandler != SIG_ERR) {
        (void) signal(SIGCHLD, sighandler); /* restore old signal handler */
    }

    D((LOG_DEBUG, "returning %d", retval));
    return retval;
}

