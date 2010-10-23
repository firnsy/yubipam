#!/bin/bash
chgrp yubiauth /etc/yubikey /sbin/yk_chkpwd
chmod g+rw /etc/yubikey
chmod g+s /sbin/yk_chkpwd
