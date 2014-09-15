#-*- coding:utf-8 -*-
# get dau

import sys
import os
import redis
import time
import logging
from bitarray import bitarray
from datetime import datetime, date, timedelta
from tornado.options import define, options

try:
    import dauconfig
except ImportError:
    raise ImportError, ("Configure file 'dauconfig.py' "
        "or module dauconfig was not found")
from aubitmap import Bitmap
import util

def stdoffset(cls):
    return cls.config.STD_OFFSET


class _Cache(object):
    __instance = None
    _cache_dict = {}
    _cache_now  = None
    _cache_alive = 60*5
    _max_cache_lens = 1024

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(_Cache, cls).__new__(cls)
        return cls.__instance

    def __init__(self):
        self._cache_dict 

    def get_cache(self, key):
        if self._cache_dict.has_key(key):
            cache, sttl = self._cache_dict.get(key)
            if time.time() - sttl > 0:
                self._kill_cache(key)
                return None
            logging.debug('got cache: %s', key)
            self._cut_cache()
            return cache
        return None
    
    def _kill_cache(self, key):
        try:
            self._cache_dict.__delitem__(key)
        except:
            pass

    def set(self, key, data, ttl=None):
        if ttl is None:
            ttl = self._cache_alive
        self._set_cache(key, data, ttl)

    def _set_cache(self, key, data, ttl=None):
        if ttl is None:
            ttl = self._cache_alive
        expireat = time.time() + ttl
        val = (data, expireat)
        self._cache_dict[key] = val
        logging.debug('save cache: %s %s %s', key, ttl, data and len(data) or 'nil') 

    def _cut_cache(self):
        while len(self._cache_dict) > self._max_cache_lens:
            if len(self._cache_dict) > 0:
                self._cache_dict.popitem()        

class AUstat():


    def __init__(self, baseday=None, redis_cli=None,
     filters=None, cache=True, config=None):
        s = time.time()
        # logging.info('init austat: baseday %s, config: %s', baseday, config and config.dau_keys_conf or '')
        if not redis_cli:
            raise KeyError,'Redis connection not found'
        if not config:
            self.config = dauconfig
        else:
            self.config = config

        self.cache = _Cache()
        # self._cache_dict          = {}
        # self._max_cache_lens = 1024
        self.REDIS          = redis_cli
        self.baseDay        = baseday
        self.filters        = filters
        self._is_cache      = cache
        self.baseBitmap     = self._make_bitmap(baseday) 
        self.newUserBitmap  = Bitmap()


    def _get_cache(self, key):
        logging.debug('get from cache: %s', key)
        return self.cache.get_cache(key)

    def _cache(self, key, value):
        if self._is_cache:
            return self.cache._set_cache(key, value)
    


    def _list_day(self, fday=None, tday=None):
        """
        return the date string list from fday to tday
        """
        date_fday   = fday or date.today()
        date_tday   = tday or date.today()
        days        = (date_tday - date_fday).days+1
        dayList     = [date_fday+timedelta(v) for v in range(days)] 
        return dayList        

    def _make_bitmap(self, day=None, Type='dau'):
        """
        initial and return dwarf.Bitmap object
        """
        # logging.info('make_bitmap:%s %s', day, Type)
        s = time.time()
        dauBitmap  = Bitmap()
        if day:
            DAU_KEY  = self.config.dau_keys_conf[Type]
            if Type in ('mau','mnu','mru'):
                dauKey   = DAU_KEY.format(month=day.strftime(self.config.MONTH_FORMAT))
            else:
                dauKey   = DAU_KEY.format(date=day.strftime(self.config.DATE_FORMAT))
            dauBitmap = Bitmap()
            cached = self._get_cache(dauKey)
            if cached:
                bitsDau = cached
                if cached is 'None':
                    bitsDau = None
            else:
                logging.debug('no cache:%s',dauKey)
                bitsDau  = self.REDIS.get(dauKey)
                self._cache(dauKey, bitsDau or 'None')
            if bitsDau:
                dauBitmap.frombytes(bitsDau)
                # logging.debug('Init bitmap:Count: %s' % (dauBitmap.count()))
                if self.filters:
                    dauBitmap.filter(self.filters)
                    # logging.info('Filter bitmap: f-%s b-%s' % (self.filters.count(), dauBitmap.count()))
            # self._cache(dauKey, dauBitmap)
        logging.debug('_make_bitmap Handler:%s %s - %s Sec' % (day,Type,time.time()-s))
        return dauBitmap

    def make_bitmap(self, day=None, Type='dau'):
        return self._make_bitmap(day, Type)


    def get_newuser_bitmap(self, day=None, Type='dnu'):
        """
        返回 day 或 day 所在月份的新用户bitmap对象
        """
        bmap = self._make_bitmap(day, Type)
        # logging.info('nbm: %s , %s', day, bmap.count())
        if bmap:
            # logging.info('nbm: %s , %s', day, bmap.length())
            return bmap
        '''
        如果没有新用户的分区间映射数据，则按照偏移量获取新用户映射数据
        '''
        Type = Type=='dnu' and 'dau' or 'mau' 
        bmap = self._get_newuser_bitmap(day, Type)
        return bmap

    def _get_newuser_bitmap(self, day=None, Type='dau'):
        """
        返回新用户当日登陆记录bitmap对象
        适配记录每日新用户id偏移量的数据存储方式
        """
        day = day or self.baseDay
        offsets = 0
        dauBitmap = Bitmap() 
        if day:
            if Type=='mau':
                day = datetime(day.year, day.month, 1)
            hKey = (self.config.dau_keys_conf['newuser'], 
                    day.strftime(self.config.DATE_FORMAT))
            # dauBitmap = self._get_cache(hKey) or dauBitmap
            # cached = self._get_cache(hKey)
            # if cached is None or True:
            if True:
                offsets = self.REDIS.hget(*hKey)
                if not offsets:
                    return dauBitmap
                offsets = int(offsets)
                bmp = ((day==self.baseDay and Type=='dau')
                 and Bitmap(self.baseBitmap) or self._make_bitmap(day, Type))
                s = time.time()
                dauBitmap = Bitmap(bmp) # 生成新的实例，避免被篡改
                dauBitmap[:offsets] = False
                # self._cache(hKey, dauBitmap)
            else:
                dauBitmap = cached
        logging.debug('get nu bitmap: %s Sec' % (time.time()-s))
        return dauBitmap

    def get_dau(self, day=None):
        """
        return the dau number
        if day is provided then return the dau of the day
        """
        if not day:
            return self.baseBitmap.count()
        return self._make_bitmap(day).count()

    def get_dnu(self, day=None):
        """
        return the daily count of new user number
        """
        if not day:
            return self.newUserBitmap.count()
        return self.get_newuser_bitmap(day).count()

    def get_dru(self, day=None):
        """
        return the daily count of new user number
        """
        if not day:
            return 0
        return self._make_bitmap(day, 'dru').count()

    def get_mau(self, date=None):
        if not date:
            date = self.baseDay
        return self._make_bitmap(date, 'mau').count()

    def get_mnu(self, date=None):
        if not date:
            date = self.baseDay
        return self.get_newuser_bitmap(date, 'mnu').count()

    def get_mru(self, date=None):
        if not date:
            date = self.baseDay
        return self._make_bitmap(date, 'mru').count()

    def list_dau(self, fday=None, tday=None):
        """
        return a list of daily active user's number from fday to tday
        list_dau(string, string) -> [(date1, number),(date2, number)....]
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList, map(self.get_dau,dayList))

    def list_dnu(self, fday=None, tday=None):
        """
        return a list of daily new user count from fday to tday
        list_dnu(string, string) -> [(date1, number),(date2, number)....]
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList, map(self.get_dnu,dayList))

    def list_dru(self, fday=None, tday=None):
        """
        return a list of daily recharge user from fday to tday
        list_dru(string, string) -> [(date1, number),(date2, number)....]
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList, map(self.get_dru, dayList))

    def list_mau(self, fday, tday):
        """
        month active user count
        list_mau(string, string) -> [(datetime1, int),(datetime2,int),....]
        """
        lMonth = util.month1stdate(fday, tday)
        return zip(lMonth, map(self.get_mau, lMonth))

    def list_mnu(self, fday, tday):
        """
        monthly new user count
        list_mnu(string, string) -> [(datetime1, int),(datetime2,int),....]
        """
        lMonth = util.month1stdate(fday, tday)
        return zip(lMonth, map(self.get_mnu, lMonth))

    def list_mru(self, fday, tday):
        """
        monthly rechange user count
        list_mnu(string, string) -> [(datetime1, int),(datetime2,int),....]
        """
        lMonth = util.month1stdate(fday, tday)
        return zip(lMonth, map(self.get_mru, lMonth))

    def mau(self, fday=None, tday=None):
        """
        return the Merged Active Users count from fday to tday
        """
        dayList = self._list_day(fday, tday)
        BaseBM  = self._make_bitmap()
        for day in dayList:
            BaseBM.merge(self._make_bitmap(day))
        return BaseBM.count()

    def get_30days_mau(self):
        """
        return the merged active user number in the last 30 days before
        self.baseDay
        """
        fday = self.baseDay-timedelta(days=30)
        return self.mau(fday=fday, tday=self.baseDay)

    def get_7days_mau(self):
        """
        return the last 7 days' active user number before baseDay
        """
        fday = self.baseDay-timedelta(days=7)
        return self.mau(fday=fday, tday=self.baseDay)

    def list_1day_renu(self,fday,tday):
        """
        return the next day's new user retained
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList,[self._get_ndays_renu(d,1) for d in dayList])

    def list_7day_renu(self,fday,tday):
        """
        return the seventh day's new user retained
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList,[self._get_ndays_renu(d,7) for d in dayList])

    def list_30day_renu(self,fday,tday):
        """
        return the thirtieth day's new user retained
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList,[self._get_ndays_renu(d,30) for d in dayList])

    def _get_ndays_renu(self,day,num):
        return self.get_newuser_bitmap(day)._and_count(
            self.make_bitmap(day+timedelta(days=num)))

    def retained(self, day):
        """
        return the retained user number of baseDay in the givend day
        """
        bm  = self._make_bitmap(day)
        return self.baseBitmap.retained(bm)

    def get_retained(self, fday, tday):
        """
        the self.baseday's daily retained number from fday to tday
        """
        dayList = self._list_day(fday, tday)
        return zip(dayList, 
            self.baseBitmap.retained_count(
                 (self._make_bitmap(day) for day in dayList)
                )
            )

    def daily_retained_list(self, fday, tday):
        """
        the fday's retained number from fday to today
        """
        dayList = self._list_day(fday,tday)
        return zip(dayList, 
            self.make_bitmap(dayList[0],'dau').retained_count(
                 (self.make_bitmap(day, 'dau') for day in dayList)
                )
            )

    def customized_retained_list(self, base_day, day_list=[]):
        """
        the  day_list's retained number from fday to today
        :param base_day: the base day
        :param day_list: eg :[datetime,datetime], should not contain base_day
        :return:
        """
        auBitmap = self.make_bitmap(base_day, 'dau')
        return [(base_day, auBitmap.count())] + \
               zip(day_list, self._retained_value(base_day, day_list, 'dau'))

    def get_month_retained(self, fday, tday):
        """
        monthly retained au count from fday's month to tday's month
        """
        lMdates1 = util.month1stdate(fday, tday)
        return zip(lMdates1,
            self.make_bitmap(lMdates1[0],'mau').retained_count(
                    (self._make_bitmap(date, 'mau') for date in lMdates1)
                )
            )

    def get_retained_nu(self, fday, tday):
        """
        return the list of newuser retained number and the date string
        """
        dayList = self._list_day(fday, tday)
        if not self.newUserBitmap:
            self.newUserBitmap = self.get_newuser_bitmap(self.baseDay)
        # logging.info('self.nUB: %s', self.newUserBitmap.count())
        return zip(dayList, 
            self.newUserBitmap.retained_count(
                 (self.make_bitmap(day) for day in dayList)
                )
            )

    def daily_nu_retained_list(self, fday, tday):
        """
        fday's newuser retained number from fday to tday
        """
        dayList = self._list_day(fday, tday)
        nuBitmap = self.get_newuser_bitmap(dayList[0])
        return [[dayList.pop(0),nuBitmap.count()]]+zip(dayList, 
            nuBitmap.retained_count(
                 (self.make_bitmap(day, 'dau') for day in dayList)
                )
            )

    def customized_nu_retained_list(self, base_day, day_list=[]):
        """
        the day_list's retained number
        :param base_day: the base day
        :param day_list: eg :[datetime, datetime], should not contain base_day
        :return:
        """
        nuBitmap = self.get_newuser_bitmap(base_day)
        return [(base_day, nuBitmap.count())] + zip(day_list,
                  self._retained_value(base_day, day_list, 'dnu'))


    def get_month_retained_nu(self, fday, tday):
        """
        Monthly newuser retained count from fday's month to tday's month
        """
        lMdates1    = util.month1stdate(fday, tday)
        MnuBitmap   = self.get_newuser_bitmap(lMdates1[0], 'mnu')
        # logging.info('Newusers count: %s', MnuBitmap.count())
        return [[lMdates1.pop(0), MnuBitmap.count()]]+zip(lMdates1,
            MnuBitmap.retained_count(
                 (self._make_bitmap(date, 'mau') for date in lMdates1)
                )
            )


    def retained_by_daylist(self, dayList):
        return zip(dayList, self.baseBitmap.retained_count(
                (self._make_bitmap(day) for day in dayList)
            ))

    def retained_nu_by_daylist(self,dayList):
        return zip(dayList, 
            self.newUserBitmap.retained_count(
                 (self._make_bitmap(day) for day in dayList)
                )
            )

    def _retained_value(self, day, day_list, Type='dau'):
        retained_list = []
        if Type == 'dau':
            day_bitmap = self.make_bitmap(day, Type)
        elif Type == 'dnu':
            day_bitmap = self.get_newuser_bitmap(day)

        for t_day in day_list:
            retained_list.append(day_bitmap._and_count(
                self.make_bitmap(t_day, 'dau')
            ))
        return retained_list

class Filter(Bitmap):
    """
    Generate AU filter object
    Need redis db to fetch the filter data
    """
    def __new__(cls, config=None, redis_cli=None, *args, **kwargs):
        return super(Filter, cls).__new__(cls, *args, **kwargs)

    def __init__(self, config=None, redis_cli=None):
        super(Filter, self).__init__()
        # logging.info('init Filter: config: %s', config and config.dau_keys_conf or '')        
        self.config    = config or dauconfig
        self.redis_cli = redis_cli
        self._cache = _Cache()

    def expand(self, redis_cli=None, **kwargs):
        """
        扩展筛选器
        pass = condition1 or condition2
        """
        redis_cli = redis_cli or self.redis_cli
        for k,v in kwargs.items():
            fBm = self._get_filter_bitmap(redis_cli, k, v)
            self.merge(fBm)
        return self

    def overlap(self, redis_cli=None, **kwargs):
        """
        叠加筛选器
        pass = condition1 and condition2
        """
        redis_cli = redis_cli or self.redis_cli
        for k,v in kwargs.items():
            fBm = self._get_filter_bitmap(redis_cli, k, v)
            self.filter(fBm)
        return self

    def _get_filter_bitmap(self, redis_cli, filtername, filterclass):
        """
        由数据源获取筛选条件 BitMap
        """
        logging.debug(self.redis_cli)
        redis_cli = redis_cli or self.redis_cli
        if not isinstance(redis_cli, redis.client.Redis):
            raise TypeError, "Need redis connection but not found"
        fKey_format = self.config.filter_keys_conf.get(filtername)
        if not fKey_format:
            raise ValueError, "Can not find the key \'%s\' in self.config.filter_keys_conf" % k
        logging.debug('%s, %s, %s',fKey_format,filtername,filterclass) 
        fKey  = fKey_format.format(**{filtername:filterclass})
        cached =  self._cache.get_cache(fKey)
        if cached is None:
            fBits = redis_cli.get(fKey)
            fBm   = Bitmap()
            if fBits:
                fBm.frombytes(fBits)
            else:
                fBm   = Bitmap('0')
            self._cache.set(fKey, fBm)
        else:
            fBm = cached
        return fBm


class AUrecord():
    """
    Do save active user's bit map record in given redis db
    """

    def __init__(self, redis_cli, config=None):
        if not redis_cli:
            raise ValueError , "Need redis client but not found!"
        self.config = config or dauconfig
        self.redis = redis_cli

    def mapActiveUserid(self, date, userid):
        """
        Save active userid
        """
        sDate     = date.strftime(self.config.DATE_FORMAT)
        mDate     = date.strftime(self.config.MONTH_FORMAT)
        reKey     = self.config.dau_keys_conf['dau'].format(date=sDate)
        moKey     = self.config.dau_keys_conf['mau'].format(month=mDate)
        redis_cli = self.get_redis_cli()
        offset    = int(userid)
        if offset > -1 and offset <= self.config.MAX_BITMAP_LENGTH:
            redis_cli.setbit(reKey, offset, 1)
            logging.debug('Save auid in redis by setbit %s %d' % (reKey, offset)) 
            redis_cli.setbit(moKey, offset, 1)
            logging.debug('Save auid in redis by setbit %s %d' % (moKey, offset)) 
            
    def mapNewUser(self, date, userid):
        """
        set new userid
        """
        sDate     = date.strftime(self.config.DATE_FORMAT)
        mDate     = date.strftime(self.config.MONTH_FORMAT)
        reKey     = self.config.dau_keys_conf['dnu'].format(date=sDate)
        moKey     = self.config.dau_keys_conf['mnu'].format(month=mDate)
        redis_cli = self.get_redis_cli()
        offset    = int(userid)
        if offset > -1 and offset <= self.config.MAX_BITMAP_LENGTH:
            redis_cli.setbit(reKey, offset, 1)
            # logging.debug('Save auid in redis by setbit %s %d' % (reKey, offset)) 
            redis_cli.setbit(moKey, offset, 1)
            # logging.debug('Save auid in redis by setbit %s %d' % (moKey, offset)) 


    def mapActiveUseridbyByte(self, date, bytes):
        """
        Save Active userid by bytes
        """
        sDate     = date.strftime(self.config.DATE_FORMAT)
        reKey     = self.config.dau_keys_conf['dau'].format(date=sDate)
        redis_cli = self.get_redis_cli()
        logging.debug('Save dau bytes: %s' % reKey)
        redis_cli.set(reKey, bytes)
        

    def mapMaufromByte(self, date, bytes):
        """
        Save Monthly Active userid by bytes
        """
        sMonth    = date.strftime(self.config.MONTH_FORMAT)
        reKey     = self.config.dau_keys_conf['mau'].format(month=sMonth)
        redis_cli = self.get_redis_cli()
        logging.debug('Save mau from bytes: %s' % reKey)
        redis_cli.set(reKey, bytes)
         

    def saveNewUserIndex(self, date, userid):
        """
        Save new user id to redis
        """
        sdate     = date.strftime(self.config.DATE_FORMAT)
        rKey      = self.config.dau_keys_conf['newuser']
        redis_cli = self.get_redis_cli()
        rVar      = int(userid)
        if rVar > 0 and rVar <=  self.config.MAX_BITMAP_LENGTH:
            redis_cli.hset(rKey, sdate, rVar)
            logging.debug('save newuser id>> hset %s %s %s' % (rKey, sdate, rVar))


    def mapFilter(self, filtername, filterclass, userid):
        """
        Save userid map in filter
        """
        # logging.info('%s, %s, %s' % (filtername, filterclass, userid))
        redis_cli = self.get_redis_cli()
        f_conf    = self.config.filter_keys_conf
        rKey      = f_conf[filtername].format(**{filtername:filterclass})
        if not rKey:
            raise ValueError, "Haven't %s filter keys" % filtername
        offset    = int(userid)-stdoffset(self)
        if offset>0 and offset <= self.config.MAX_BITMAP_LENGTH:
            redis_cli.setbit(rKey, offset, 1)
            logging.debug('Save auid in redis by setbit %s %d 1' % (rKey, offset)) 
            

    def mapRechargeUser(self, date, userid):
        """
        set recharge user
        """
        sDate     = date.strftime(self.config.DATE_FORMAT)
        mDate     = date.strftime(self.config.MONTH_FORMAT)
        reKey     = self.config.dau_keys_conf['dru'].format(date=sDate)
        moKey     = self.config.dau_keys_conf['mru'].format(month=mDate)
        redis_cli = self.get_redis_cli()
        offset    = int(userid)
        if offset > -1 and offset <= self.config.MAX_BITMAP_LENGTH:
            redis_cli.setbit(reKey, offset, 1)
            redis_cli.setbit(moKey, offset, 1)

    def get_redis_cli(self):
        return self.redis

