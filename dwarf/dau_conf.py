#!/usr/bin/env python
#-*- coding: utf-8 -*-

DATETIME_FORMAT     = '%Y-%m-%d %H:%M:%S'
DATE_FORMAT         = "%Y%m%d"
MONTH_FORMAT        = "%Y%m"
DATE_FORMAT_R       = '%Y-%m-%d'
STD_OFFSET          = 0
MAX_BITMAP_LENGTH   = 1000*1000*200
BITMAP_BLK_LEN      = 1000*1000*20
BITMAP_BLK_PREFIX   = "%d-{key}"

# Keys name of main data in redis
dau_keys_conf = dict(
    dau     = "sDau:{date}",
    newuser = "hNewUser",
    mau     = "sMau:{month}",
    dnu   = "sDnu:{date}",
    mnu   = "sMnu:{month}",
    dru   = "sDru:{date}",
    mru   = "sMru:{month}",
)

# Keys name for filter data in redis
filter_keys_conf = dict(
    gender      = "sFgender:{gender}",
    platform    = "sFplatform:{platform}",
    version     = "sFversion:{version}",
    channel     = "sFchannel:{channel}",
    regu        = "sFregu:{regu}",
)
