#!/usr/bin/env python
#coding: utf-8
#name: Mapping the newuserid and filter
#by Camelsky 2013-02-20

import logging
try:
    import MySQLdb
    import redis
except:
    print 'Need python modules \'redis\' and \'MySQLdb\' but no found! '
    exit(1)
import tornado
try:
    import torndb
    database = torndb
except:
    from tornado import database
from tornado.options import options, define
from datetime import date, datetime, timedelta
import time
import dauconfig
# import dwarf.dau
import dwarf.daux
from dwarf.daux import AUrecord
from dwarf.aubitmap import Bitmap
import util
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



def get_mysql():
    conf = db_config.mysql_conf
    conn = database.Connection(
        host="%s:%s" % (conf['host'], conf['port']), 
        database=conf['db'], 
        user=conf['user'], 
        password=conf['passwd'], 
    )
    return conn

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

def get_promo_redis():
    conf = db_config.redis_promo_conf
    try:
        conn = redis.Redis(**conf)
        return conn
    except Exception, e:
        raise e

def getNewUserid(date, mysql_conn):
    sql  = "select id from user where create_time >= %s order by id limit 1"
    conn = mysql_conn
    if not mysql_conn:
        conn = get_mysql()
    logging.info(sql % date) 
    ret = conn.get(sql, date)
    if ret:
        uid = ret['id']
        return uid
    else:
        return 0

def getAllNewUserid(from_date, to_date, mysql_conn):
    to_date = to_date+timedelta(1)
    sql = "select date(create_time) as date,id from user where create_time >= %s and create_time < %s"
    logging.info(sql % (from_date, to_date))
    ret = mysql_conn.iter(sql, from_date, to_date)
    return ret


def getGenderUserid(from_date=None, mysql_conn=None):
    conn = mysql_conn
    if not mysql_conn:
        conn = get_mysql()
    sql     = "select id , gender from user %(where)s "
    sWhere  = ""
    args    = []
    if from_date:
        sWhere += "create_time >= %s"
        args += [from_date]
    sWhere = (sWhere and sWhere.lower().find('where') < 0) and ' where %s ' % sWhere or sWhere 
    sql = sql % {'where' : sWhere}
    logging.info(sql, *args)
    return conn.iter(sql, *args)

def getRegUser(from_date=None, mysql_conn=None):
    conn   = mysql_conn
    sql = "select user_id, userinfo_status from user_statics %(where)s"
    sWhere = ""
    args    = []
    if from_date:
        sWhere += sWhere.lower().find('where')<=0 and 'where ' or ''
        sWhere += "and create_time >= %s "
        args += [from_date]
    
    sWhere = (sWhere and sWhere.lower().find('where') < 0) and ' where %s ' % sWhere or sWhere 
    
    sql  = sql % {'where' : sWhere}
    logging.info(sql, *args)
    return conn.iter(sql, *args)

def getVersionUserid(from_date=None, mysql_conn=None):
    conn = mysql_conn
    sql  = "select client_version, user_id from user_statics %(where)s"
    sWhere = ''
    args   = []
    if from_date:
        sWhere += " create_time >= %s" 
        args += [from_date]

    sWhere = (sWhere and sWhere.lower().find('where') < 0) and ' where %s ' % sWhere or sWhere 

    sql  = sql % {'where' : sWhere}
    logging.info(sql, *args)
    return conn.iter(sql, *args)

def getUAfromdb(from_date=None, mysql_conn=None):
    conn = mysql_conn
    sql  = "select a.id, (select ua from user_ua_record where user_id = a.id limit 1) as ua from user a %(where)s"
    sWhere = ''
    args   = []
    if from_date:
        sWhere += " a.create_time >= %s "
        args = [from_date]

    sWhere = (sWhere and sWhere.lower().find('where') < 0) and " where %s " % sWhere or sWhere 

    sql  = sql % {'where' : sWhere}
    logging.info(sql, *args)
    return conn.iter(sql, *args)

def getUAuser(from_date=None, mysql_conn=None):
    conn = mysql_conn
    for v in getUAfromdb(from_date, mysql_conn):
        user_id = v.id
        uainfo  = util.splitUa(v.ua)
        uainfo.update(user_id=user_id)
        logging.debug("uainfo: %s " % uainfo)
        yield uainfo


def DateList(from_date, to_date):
    days        = (to_date-from_date).days+1
    dateList    = [from_date+timedelta(v) for v in range(days)] 
    return dateList


def idList(dates, mysql_conn):
    for date in dates:
        yield getNewUserid(date, mysql_conn)


def mapNewUserid(dates, userids):
    auRecord = AUrecord(get_redis_client())
    map(auRecord.saveNewUserIndex, dates, userids)

def setNewUserid(date, userid):
    ar = AUrecord(get_redis_client())
    ar.mapNewUser(date, userid)

def mapMau(fdate, tdate):
    auR     = dwarf.dau.AUrecord(get_redis_client())
    auS     = dwarf.dau.AUstat(redis_cli=get_redis_client())
    lMonth  = util.monthdates(fdate, tdate)
    for row in lMonth:
        bitMau = auS.make_bitmap(row[0], 'mau')
        bitMau.merge(*map(auS.make_bitmap, row))
        auR.mapMaufromByte(row[0], bitMau.tobytes())

def getPromoChannel(fdate, tdate):
    fts = time.mktime(fdate.timetuple())
    tts = time.mktime(tdate.timetuple())
    conn = get_mysql()
    for channel, did in _awaked_devices(fts, tts):
        user_id = _get_did_userid(did, conn)
        if user_id:
            logging.debug('%s-%s', channel, user_id)        
            yield channel, user_id

def _get_awaked_udids(fts,tts):
    key = 'zAwakedD'
    re  = get_promo_redis()
    udids = re.zrangebyscore(key, fts, tts)
    if udids:
        return udids
    return []

def _awaked_devices(fts, tts):
    key = 'hAwakeD:{}'
    udids = _get_awaked_udids(fts, tts)
    re = get_promo_redis()
    for udid in udids:
        channel,did = re.hmget(key.format(udid), 'channel', 'did')
        yield channel,did

def _get_did_userid(did, conn):
    if not did:
        return None
    sql = "select user_id from device_record where device_id = %s order by id desc limit 1"
    logging.debug(sql, did)
    ret = conn.get(sql, did)
    if ret:
        return ret.get('user_id')
    return None


def doMap(do, from_date, to_date, auRecord, mysql_conn):
    domap = {
        'gender': lambda:[auRecord.mapFilter('gender', v.gender, v.id) for v in getGenderUserid(from_date, mysql_conn)],
        'regu': lambda:[auRecord.mapFilter('regu', v.userinfo_status, v.user_id) for v in getRegUser(None, mysql_conn)],
        'version': lambda:[auRecord.mapFilter('version', (v.client_version or 'unknown').encode('utf-8'), v.user_id) for v in getVersionUserid(from_date, mysql_conn)],
        'uainfo': lambda:[(auRecord.mapFilter('platform', v['platform'], v['user_id']),
            auRecord.mapFilter('channel', v['channel'], v['user_id'])) for v in getUAuser(from_date, mysql_conn)],
        'nuid': lambda: [auRecord.mapNewUser(v['date'], v['id']) for v in getAllNewUserid(from_date,to_date, mysql_conn)],
        'promo': lambda: [ auRecord.mapFilter('channel', channel, uid)
            for channel, uid in getPromoChannel(from_date, to_date)],
    }
    if do == 'all':
        return [v() for v in domap.values()]
    if domap.get(do):
        return domap.get(do)()
    raise ValueError, "-do=%s is not known command" % do

def run():
    define("f", default=None)
    define("t", default=None)
    define("do", help="what need to do? \'nu\'(new user) or \'all\'",default='nuid')
    tornado.options.parse_command_line()

    #计算时间范围
    Today_date      = datetime.today()
    Yesterday_date  = datetime.today()-timedelta(days=1)
    sToday_date     = Today_date.strftime(config.DATE_FORMAT)
    sYesterday_date = Yesterday_date.strftime(config.DATE_FORMAT)
    if not options.f : 
        options.f = sYesterday_date
    if not options.t :
        options.t = sYesterday_date

    try:
        if options.f == 'n':
            from_date = None
        else:
            from_date   = datetime.strptime(options.f, config.DATE_FORMAT)
        to_date     = datetime.strptime(options.t, config.DATE_FORMAT)
    except ValueError, e:
        raise e
    
    mysql_conn = get_mysql()
    if options.do == 'nu':
        auRecord = dwarf.dau.AUrecord(get_redis_client(True))
        dates = DateList(from_date, to_date)
        users = idList(dates, mysql_conn)
        map(auRecord.saveNewUserIndex, dates, users)
    elif options.do == 'mau':
        mapMau(from_date, to_date)
    else:
        auRecord = dwarf.daux.AUrecord(get_redis_client(pipe=True))
        doMap(options.do, from_date, to_date, auRecord, mysql_conn)


if __name__ == '__main__':
    s = time.time()
    run()
    e = time.time()
    print "Elapsed:",e-s,"sec"
