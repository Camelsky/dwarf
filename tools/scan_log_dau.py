#!/usr/bin/env python
#coding: utf-8
#name: scan log
#by Camelsky 2012/02/19

import os
import re
import tornado
import time
import gzip
from bitarray import bitarray
from tornado.options import options, define
from datetime import date, datetime, timedelta
try:
    import redis
except:
    print("Need python module \'redis\' but not found!")
    exit(1)
import dauconfig
import dwarf.dau
import dwarf.daux
import logging
import db_config

config = dauconfig

class redisPipeline:
    conn = None
    count = 0
    def __init__(self, conf):
        r = redis.Redis(host=conf['host'], port=conf['port'], db=conf['db'])
        self.conn = r.pipeline()
    def __del__(self):
        self._save()
        
    def _save(self):
        self.conn.execute()
        
    def setbit(self, reKey, offset, identfy=1):
        self.conn.setbit(reKey, offset, identfy)
        self.count += 1
        if self.count & 0xFF == 0:
            self._save()

def get_redis_client(pipe=False):
    conf = db_config.redis_conf
    try:
        if pipe:
            conn = redisPipeline(conf)
        else:
            conn = redis.Redis(**conf)
        return conn
    except Exception, e:
        print "redis connection Error!", e
        raise e

def markActiveUserid(date, userid, redis_cli):
    # redis_cli = get_redis_client()
    auRecord = dwarf.daux.AUrecord(redis_cli)
    if auRecord.mapActiveUserid(date,userid):
        print date, userid

def scanLogFile(date):
    fconf     = config.logfile_conf
    filename  = fconf['dir']+fconf['name_format'].format(date=date)
    print('open log file:', filename)
    if re.search('.gz$', filename):
        f = gzip.open(filename, 'rb')
    else:
        f = open(filename, 'r')
    uids  = []
    count = 0
    while 1:
        line = f.readline()
        if line:
            regmatch = re.search('from=[\'|"]([0-9]+)[\'|"]', line)
            if regmatch:
                uids.append(regmatch.group(1))
                count += 1
                if count & 0xFFFF == 0:
                    yield uids
                    uids = []
        else:
            yield uids
            f.close()
            break

def openLogFile(filename):
    if re.search('.gz$', filename):
        print('open log file:', filename)
        f = gzip.open(filename, 'rb')
    else:
        print('open log file:', filename)
        f = open(filename, 'r')
    return f

def genMapbytes(barr, uid):
    bLen   = barr.length()
    offset = int(uid)
    if offset > 0 and offset <= config.MAX_BITMAP_LENGTH:
        if bLen < offset:
            barr += bitarray(1)*(offset-bLen)
        barr[offset] = True
    return barr


def doScan(from_date, to_date, port='9022'):
    """
    扫瞄from_date 到 to_date 之间的request日志
    将每日访问用户id映射入bitmap
    """
    print from_date, to_date
    days        = (to_date-from_date).days+1
    dateList    = [from_date+timedelta(v) for v in range(days)] 
    redis_cli   = get_redis_client()
    auRecord = dwarf.daux.AUrecord(redis_cli)
    for date in dateList:
        sDate = date.strftime(config.DATE_FORMAT)
        print 'scan', sDate
        s = time.time()
        for uids in scanLogFile(sDate):
            [auRecord.mapActiveUserid(date,uid) for uid in set(uids)]
        e = time.time()
        print 'Elapsed:', e-s,'sec'

def run():
    define("f", default=None)
    define("t", default=None)
    define("port", default='9022')
    tornado.options.parse_command_line()

    #计算扫瞄日志的时间范围
    Today_date      = date.today()
    Yesterday_date  = date.today()-timedelta(days=1)
    sToday_date     = Today_date.strftime(config.DATE_FORMAT)
    sYesterday_date = Yesterday_date.strftime(config.DATE_FORMAT)
    if not options.f : 
        options.f = sYesterday_date
    if not options.t :
        options.t = sYesterday_date

    try:
        from_date   = datetime.strptime(options.f, config.DATE_FORMAT)
        to_date     = datetime.strptime(options.t, config.DATE_FORMAT)
    except ValueError, e:
        raise e

    doScan(from_date, to_date)



if __name__ == '__main__':
    run()