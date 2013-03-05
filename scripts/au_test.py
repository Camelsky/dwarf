#!/usr/bin/env python
#coding: utf-8
#name: au test
# by camel 2013/02/22

import redis 
import time
from datetime import datetime, timedelta
import logging  
import tornado
from tornado.options import options, define
import dauconfig
import dwarf.dau

config = dauconfig
def get_redis_client(pipe=False):
    conf = config.redis_conf
    try:
        if pipe:
            conn = redisPipeline(conf)
        else:
            conn = redis.Redis(**conf)
        return conn
    except Exception, e:
        print "redis connection Error!", e
        raise e


def run():
    define('day', help="The base date",default=None)
    define('f', help="From date", default=None)
    define('t', help="To date", default=None)
    options.parse_command_line()
    
    bday = options.day and datetime.strptime(options.day, config.DATE_FORMAT) or datetime.today()
    fday = options.f and datetime.strptime(options.f, config.DATE_FORMAT) or 0
    tday = options.t and datetime.strptime(options.t, config.DATE_FORMAT) or 0
    redis_cli = get_redis_client()
    filters   = None#dwarf.dau.Filter().expand(redis_cli, gender=0).overlap(redis_cli, regu=1)
    # print filters.count()
    au = dwarf.dau.AUstat(bday, redis_cli, filters= filters)
    print "baseDay:", bday , "from:" , fday, "to:", tday

    # s = time.time()
    # print "dau:", au.get_dau(), time.time()-s
    # s = time.time()
    # print "dnu:", au.get_dnu(), time.time()-s
    # s = time.time()
    # print "listdau:", au.list_dau(fday=fday, tday=tday), time.time()-s
    # s = time.time()
    # print "listdnu:", au.list_dnu(fday=fday, tday=tday), time.time()-s
    # s = time.time()
    # print "mau:", au.mau(fday=fday, tday=tday), time.time()-s
    s = time.time()
    print "retained:" , au.get_month_retained(fday=fday, tday=tday), time.time()-s
    # s = time.time()
    # print "new user retained:", au.get_retained_nu(fday=fday, tday=tday), time.time()-s
    # s = time.time()
    # print "30mau:", au.get_30days_mau(), time.time()-s

if __name__ == '__main__':
    # redis_cli = get_redis_client()
    # filters = dwarf.dau.Filter().expand(redis_cli, gender=0).overlap(redis_cli,regu=0)
    # print filters.count()
    run()
