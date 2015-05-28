#!/usr/bin/env python
#coding:utf-8
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
import log_config

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


def mark_active_userid(date, userid, redis_cli):
    auRecord = dwarf.daux.AUrecord(redis_cli)
    if auRecord.mapActiveUserid(date,userid):
        print date, userid

def get_subdirs():
    fconf = log_config
    ds = os.listdir(fconf.log_dir)
    logging.debug(ds)
    subdirs = []
    for name in ds:
        if re.match(fconf.log_subdir, name):
            dirname = os.path.join(fconf.log_dir, name)
            if os.path.isdir(dirname):
                subdirs.append(dirname)
    return subdirs

def scan_tomcat_log(date):
    fconf = log_config
    subdirs = get_subdirs()
    logging.debug(subdirs)
    for dirname in subdirs:
        logging.debug(dirname)
        filename = fconf.log_filename.format(date=date)
        filename = os.path.join(dirname, filename)
        logging.debug(filename)
        with open_file(filename) as f:
            uids = []
            count = 0
            for line in f:
                # reg = re.search(fconf.log_pattern, line)
                l = line.split()
                # if reg:
                if len(l)>11:
                    # uids.append(reg.group(1))
                    uids.append(l[10])
                    count += 1
                    if count & 0xFFF == 0:
                        yield uids
                        uids = []
                        count = 0
            yield uids

def open_file(filename):
    if re.search('.gz$', filename):
        print('open log file:', filename)
        f = gzip.open(filename, 'rb')
    else:
        print('open log file:', filename)
        f = open(filename, 'r')
    return f

def doScan(from_date, to_date):
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
        sDate = date.strftime(config.DATE_FORMAT_R)
        print 'scan', sDate
        s = time.time()
        for uids in scan_tomcat_log(sDate):
            [auRecord.mapActiveUserid(date,uid) for uid in set(uids)]
        e = time.time()
        print 'Elapsed:', e-s,'sec'

def run():
    define("f", default=None)
    define("t", default=None)
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
