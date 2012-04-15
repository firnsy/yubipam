/*
* YubiKey PAM Version Module
*
* Copyright (C) 2012 Jeroen Nijhof <jeroen@jeroennijhof.nl>
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
#include "ykversion.h"

void showVersion(const char *title) {
    fprintf(stderr, "\n"
        "%s\n"
        "Version %s.%s.%s (Build %s)\n\n"
        "Originally written by the SecurixLive team,\n"
        "Current maintainer Jeroen Nijhof <jeroen@jeroennijhof.nl>,\n"
        "Project page http://sourceforge.net/projects/pam-yubikey\n"
        "\n", title, VER_MAJOR, VER_MINOR, VER_REVISION, VER_BUILD);
}

