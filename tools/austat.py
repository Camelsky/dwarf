#!/usr/bin/env python
#coding:utf-8
#name: au stat tools
#discript: 获取活跃用户数据统计的命令行工具
#by camel 2013-02-28

import logging
import sys
import time
from datetime import datetime, timedelta
import redis 
import tornado
from tornado.options import options, define
# import dauconfig
import db_config
import dwarf
import dwarf.dau_conf
import dwarf.dau
import dwarf.daux

# config    = dauconfig
class austat():
    def __init__(self, baseDay=None, filters=None):
        self.redis_cli = self._get_redis_client()
        self.filters   = filters
        self.au        = self._instance_au(baseDay)

    def _instance_au(self, baseDay=None):
        return dwarf.daux.AUstat(baseDay, self.redis_cli, filters=self.filters, cache=True)

    def _get_redis_client(self):
        "instance redis connection "
        conf = db_config.redis_conf
        conn = None
        try:
            conn = redis.Redis(**conf)
            return conn
        except Exception, e:
            print "redis connection Error!", e
            raise e

    def dau_list(self, from_date, to_date):
        """
        list dau from from_date to to_date
        """
        return self.au.list_dau(fday=from_date, tday=to_date)

    def dnu_list(self, from_date, to_date):
        """
        list daily newuser from 'from_date' to 'to_date'
        """
        return self.au.list_dnu(fday=from_date, tday=to_date)

    def dru_list(self, from_date, to_date):
        """
        list daily recharge user from 'from_date' to 'to_date'
        """
        return self.au.list_dru(fday=from_date, tday=to_date)

    def dau_retained(self, from_date, to_date):
        """
        活跃用户留存列表
        """
        lDate = dwarf.util.list_day(fday=from_date, tday=to_date)
        ret = [['firstdate']]
        ret[0].extend(["+%s day" % (v-from_date).days for v in lDate])
        while lDate:
            row = [lDate[0]]
            if lDate:
                fday    = lDate[0]
                tday    = lDate[-1]
                lret    = self.au.daily_retained_list(fday, tday)
                row.extend([v[1] for v in lret])
            ret.append(row)
            lDate.pop(0)

        return ret

    def mau_retained(self, fdate, tdate, Type='mau'):
        """
        月度活跃用户留存表
        """
        lMdates1 = dwarf.util.month1stdate(fdate, tdate)
        ret = [['firstmonth']]
        ret[0].extend(["+%s Month" % ((v.year-fdate.year)*12+(v.month-fdate.month)) for v in lMdates1])
        while lMdates1:
            row = [lMdates1[0]]
            if Type=='mnu':
                row.extend([v[1] for v in self.au.get_month_retained_nu(lMdates1[0], lMdates1[-1])])
            else:
                row.extend([v[1] for v in self.au.get_month_retained(lMdates1[0], lMdates1[-1])])
            ret.append(row)
            lMdates1.pop(0)
        return ret

    def dnu_retained(self, from_date, to_date):
        """
        新增用户留存表
        """
        lDate = dwarf.util.list_day(fday=from_date, tday=to_date)
        ret = [['firstdate']]
        ret[0].extend(["+%s day" % (v-from_date).days for v in lDate])
        while lDate:
            # self.au.baseDay = lDate.pop(0)
            # self.au.newUserBitmap = self.au.get_newuser_bitmap(self.au.baseDay)
            # row = [self.au.baseDay]
            # row.append(self.au.newUserBitmap.count())
            row = [lDate[0]]
            if lDate:
                fday    = lDate[0]
                tday    = lDate[-1]
                lret    = self.au.daily_nu_retained_list(fday, tday)
                row.extend([v[1] for v in lret])
            ret.append(row)
            lDate.pop(0)
        return ret

    def list_dau_30mu(self, from_date, to_date):
        lDau = self.dau_list(from_date, to_date)
        lmu  = [self._instance_au(v[0]).get_30days_mau() for v in lDau]
        ret  = zip([v[0] for v in lDau], (v[1] for v in lDau), (v for v in lmu))
        ret[:0] = [('date','dau','mau')]
        return ret

    def list_dau_7mu(self, from_date, to_date):
        lDau = self.dau_list(from_date, to_date)
        lmu  = [self._instance_au(v[0]).get_7days_mau() for v in lDau]
        ret  = zip([v[0] for v in lDau], (v[1] for v in lDau), (v for v in lmu))
        ret[:0] = [('date','dau','wau')]
        return ret

def do(value, As, fday, tday):
    doing = {
        'dau': lambda:As.au.get_dau(),
        'dnu': lambda:As.au.get_dnu(As.au.baseDay),
        'mau': lambda:As.au.get_mau(),
        'mnu': lambda:As.au.get_mnu(As.au.baseDay),
        'ldau': lambda:As.dau_list(fday, tday),
        'ldnu': lambda:As.dnu_list(fday,tday),
        'ldru': lambda:As.dru_list(fday,tday),
        'lmau': lambda:As.au.list_mau(fday, tday),
        'lmnu': lambda:As.au.list_mnu(fday, tday),
        'lmru': lambda:As.au.list_mru(fday, tday),
        'reau': lambda:As.dau_retained(fday,tday),
        'remau': lambda:As.mau_retained(fday, tday, 'mau'),
        'renu': lambda:As.dnu_retained(fday,tday),
        'remnu': lambda:As.mau_retained(fday, tday, 'mnu'),
        'daumau': lambda:As.list_dau_30mu(fday, tday),
        'dauwau': lambda:As.list_dau_7mu(fday, tday),

    }
    if doing.get(value):
        return doing.get(value)()
    raise ValueError, "-do=%s is not known command" % value

def run():
    s = time.time()
    define('day', help="The base date",default=None)
    define('f', help="From date", default=None)
    define('t', help="To date", default=None)
    define('filter', help="filtername", default=None)
    define('do', help="What need to do", default='dau')
    options.parse_command_line()
    bday = options.day and datetime.strptime(options.day, dwarf.dau_conf.DATE_FORMAT) or None
    fday = options.f and datetime.strptime(options.f, dwarf.dau_conf.DATE_FORMAT) or None
    tday = options.t and datetime.strptime(options.t, dwarf.dau_conf.DATE_FORMAT) or None
    lfilter = options.filter and str.split(options.filter, ';') or []
    filters = None
    if lfilter:
        redis_cli = redis.Redis(**db_config.redis_conf)
        for v in lfilter:           
            name, vals = v.split('=')
            vals = vals.split(',')
            ff = dwarf.daux.Filter(cache_cli=redis_cli)
            for val in vals:
                ff.expand( **{name:val})
            filters = filters and filters.filter(ff) or ff

    print 'BaseDay,',options.day or ''
    print 'TimeRange,', options.f or '', '~', options.t or ''
    print 'StatType,' , options.do or ''
    # print 'Filter,', lfilter,',count,',filters and filters.count() or 0, type(filters)
    print 'Filter,', lfilter,',count,', type(filters)
    As  = austat(bday, filters)
    logging.debug(time.time()-s)
    ret = do(options.do, As, fday, tday)
    logging.debug(time.time()-s)
    try:
        for v in ret:
            for i in range(len(v)):
                if isinstance(v[i], datetime):
                    val = v[i].strftime(dwarf.dau_config.DATE_FORMAT_R) 
                else: val = str(v[i])
                sys.stdout.write(val)
                sys.stdout.write(',')
            sys.stdout.write('\n')
        logging.debug(time.time()-s)
    except Exception, e:
        print ret

if __name__ == '__main__':
    s = time.time()
    run()
    e = time.time()
    print "Time Elapsed:", e-s, "Sec"




