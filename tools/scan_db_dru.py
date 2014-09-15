#!/usr/bin/python
# coding=utf-8
import logging
import sys
import math

logging.basicConfig(
    format="%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s : "
           "%(message)s",
    level=logging.INFO
)

try:
    import MySQLdb
    import redis
except:
    print 'Need python modules \'redis\' and \'MySQLdb\' but no found! '
    exit(1)

import argparse

from datetime import datetime, timedelta
import time
import dauconfig
import dwarf.daux
from dwarf.daux import AUrecord
import db_config

config = dauconfig


class numCounter():
    count = 0

    def __init__(self, max=0):
        self.max = max

    def p_count(self):
        self.count += 1
        per = float(self.count * 100) / self.max
        sys.stdout.write("%.2f%%" % per +
                         "(%s/%s)" % (self.count, self.max) +
                         "  " + "#" * int(math.ceil(per / 10)) +
                         "\r")
        sys.stdout.flush()

    def end(self):
        print ""


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


def get_mysql():
    conf = db_config.mysql_conf
    conn = MySQLdb.connect(
        host=conf['host'],
        db=conf['db'],
        port=conf['port'],
        user=conf['user'],
        passwd=conf['passwd'],
        charset=conf['charset']

    )
    return conn


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


def get_recharge_users(f_date, t_date, mysql_conn):
    sql = "select complete_time,user_id from user_order where status=2 "
    if f_date:
        sql += " and complete_time >='%s'" % f_date.strftime("%Y-%m-%d")
    if t_date:
        sql += " and complete_time <='%s'" % t_date.strftime("%Y-%m-%d")

    logging.info("get recharge user sql is : %s" % sql)

    cursor = mysql_conn.cursor()
    n = cursor.execute(sql)
    counter = numCounter(n)
    for row in cursor.fetchall():
        counter.p_count()
        yield row
    counter.end()


def do_map(from_date, to_date, au_record, mysql_conn):
    for row in get_recharge_users(from_date, to_date, mysql_conn):
        au_record.mapRechargeUser(*row)


def parse_datetime(value):
    try:
        return datetime.strptime(value, config.DATE_FORMAT)
    except ValueError:
        raise argparse.ArgumentTypeError("时间'%s'格式输入不正确" % value)


def run():
    parser = argparse.ArgumentParser(description="从db中同步付费到redis",
                                     argument_default=None,
                                     add_help=True)
    parser.add_argument("-f", "--from_date",
                        type=parse_datetime,
                        default=None,
                        help="开始时间，如:20140101,默认无开始时间")
    parser.add_argument("-t", "--to_date",
                        required=False,
                        default=datetime.today(),
                        type=parse_datetime,
                        help="截止时间，格式如20140131,默认为当天")

    args = parser.parse_args()
    logging.info("参数为：%s" % args)

    mysql_conn = get_mysql()
    au_record = dwarf.daux.AUrecord(get_redis_client(pipe=True))
    do_map(args.from_date, args.to_date, au_record, mysql_conn)


if __name__ == '__main__':
    s = time.time()
    run()
    e = time.time()
    print "Elapsed:", e - s, "sec"
