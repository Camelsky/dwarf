# coding:utf-8
# create by Camel
# at 2014-07-01

import logging
import time
from datetime import datetime, timedelta

import dau
import util
import dau_conf
config = dau_conf

class dauxBase(object):

    def _keyprefix_chain(self):
        '''
        生成区间数据前缀列表
        '''
        plus = config.MAX_BITMAP_LENGTH % config.BITMAP_BLK_LEN and 1 or 0
        nodes = range(config.MAX_BITMAP_LENGTH/config.BITMAP_BLK_LEN + plus)
        pres  = []
        for node in nodes:
            if node:
                pres.append(config.BITMAP_BLK_PREFIX % node)
            else:
                pres.append('{key}')
        return pres

    def _define_config(self, pref):
        '''
        根据统计区间返回区间配置
        '''
        dau_keys_conf = dict()
        filter_keys_conf = dict()
        for k,v in self.config.dau_keys_conf.items():
            dau_keys_conf[k] = pref.format(key=v)
        for k,v in self.config.filter_keys_conf.items():
            filter_keys_conf[k] = pref.format(key=v)
        return auconfig(dau_keys_conf, filter_keys_conf)

    def _get_uid_pos(self, uid):
        '''
        uid must be int or long
        确定一个数值（如，userid）的映射区间值
        '''
        pos =  int(uid/self.config.BITMAP_BLK_LEN) 
        return pos 

    def _uid_pos_offset(self, uid):
        '''
        返回uid再所属区间及在此区间的偏移量
        '''
        pos    = self._get_uid_pos(uid)
        offset = uid % self.config.BITMAP_BLK_LEN
        return (pos, offset)
    


class AUstat(dauxBase):
    
    def __init__(self, baseday=None, cache_cli=None,
      cache=True, filters=None):
        if not cache_cli:
            raise KeyError, 'have no cache server connection'
        self.baseDay = baseday
        self.cache_cli = cache_cli
        self.config  = dau_conf
        self.prefixs = self._keyprefix_chain()
        self.filters = filters
        self.is_cache = cache
        self._dau_ins = {}
        if self.filters:
            logging.debug(self.filters.operation_inner)
            logging.debug(self.filters.operation_ext)

    def _sum_result(self, rows):
        '''
        将分区间返回结果累加得到汇总值
        _sum_result([[i1,i3],[i2,i4]]) -> [[i1+i2,i3+i4]]
        _sum_result([[(date1,i1),(date2,i3)],[(date1,i2),(date2,i4)]] -> 
            [[date1,i1+i2],[date2,i3+i4]]
        '''
        total  = 0
        totals = 0
        for item in rows:
            if isinstance(item, long) or isinstance(item, int):
                total += item
            elif isinstance(item, list) or isinstance(item, tuple):
                if totals:
                    totals = map(lambda x,y:[x[0],x[1]+y[1]], totals, item)
                else:
                    totals = item
            else:
                totals = rows
                break
        logging.debug(totals)
        return total or totals


    def _init_austats(self):
        '''
        按区间配置实例化 dau.AUstat 并返回
        '''
        for prefix in self.prefixs:
            if self._dau_ins.get(prefix, None):
                aus = self._dau_ins.get(prefix)
            else:
                _config = self._define_config(prefix)
                filters = self.filters
                if self.filters:
                    filters = self.filters.ins_filter(_config=_config)
                    logging.debug('%s %s', prefix, filters.count())
                aus = dau.AUstat(self.baseDay, 
                    redis_cli=self.cache_cli, filters=filters, 
                    cache=self.is_cache, config=_config)
                self._dau_ins[prefix] = aus
            yield aus 

    def _call_austat(self, name, *args, **kwargs):
        '''
        查找并执行各区间AUstat实例下的‘name’函数
        迭代返回结果
        '''
        for aus in self._init_austats():
            yield getattr(aus, name)(*args, **kwargs)
    

    def _func_bridge(self, name):
        def func(*args, **kwargs):
            rows = self._call_austat(name, *args, **kwargs)
            ret = self._sum_result(rows)
            return ret 
        return func 


    def __getattr__(self, name):
        try:
            return self._func_bridge(name)
        except Exception:
            raise KeyError, "'%s' is not defined" % name


class Filter(dauxBase):
    """
    dau.Filter 的区间映射
    """

    def __init__(self, cache_cli):
        if not cache_cli:
            raise KeyError, 'have no cache service connection'
        self.cache_cli = cache_cli
        self.expands = []
        self.overlaps = []
        self.operation_inner = []
        self.operation_ext   = []

    def expand(self, **kwargs):
        self.operation_inner.append(('expand',kwargs))
        return self

    def overlap(self, **kwargs):
        self.operation_inner.append(('overlap',kwargs))
        return self

    def _ins_filter(self, _config):
        '''
        实例化过滤器实例
        '''
        ft = dau.Filter(config=_config)
        for item in self.operation_inner:
            getattr(ft, item[0])(self.cache_cli,**item[1])
        logging.debug('opin:%s, fc:%s',self.operation_inner, ft.count())
        return ft

    def ins_filter(self, _config):
        '''
        生成过滤器实例并其它规则过滤器合并过滤
        返回操作后的过滤器实例
        '''
        ft = self._ins_filter(_config)
        for item in self.operation_ext:
            getattr(ft, item[0])(item[1]._ins_filter(_config)) 
        logging.debug(ft and ft.count() or None)
        return ft

    def filter(self, ff):
        self.operation_ext.append(('filter', ff))
        return self

    def merge(self, ff):
        self.operation_ext.append(('merge', ff))
        return self

class AUrecord(dauxBase):

    def __init__(self, redis_cli):
        self.cache_cli = redis_cli
        self.config    = dau_conf
        self.prefixs   = self._keyprefix_chain()
        self._ins_AUR  = self._init_aurecord()

    def _init_aurecord(self):
        '''
        按区间配置实例化 dau.AUstat 并返回
        '''
        ins = []
        for prefix in self.prefixs:
            _config = self._define_config(prefix)
            aur = dau.AUrecord(self.cache_cli, config=_config)
            ins.append(aur)
        return ins 

    def _call_aurecord(self, name, userid, **kwargs):
        try:
            uid = int(userid)
        except Exception, e:
            logging.warning('wrong userid: %s %s', type(userid), userid)
            return
        pos, uid_offset = self._uid_pos_offset(uid)
        logging.debug('%s, %s, %s, %s', name, userid, pos,uid_offset)
        aur = self._ins_AUR[pos]
        getattr(aur, name)(userid=uid_offset, **kwargs)

    def mapActiveUseridbyByte(self, date, bytes):
        raise "don't support this function"

    def mapMaufromByte(self, date, bytes):
        raise "don't support this function"        


    def _func_makeup(self, name):
        if name in ('mapFilter'):
            def func(filtername, filterclass, userid):
                return self._call_aurecord(name, userid,
                 filtername=filtername, filterclass=filterclass)
        else:
            def func(date, userid):
                return self._call_aurecord(name, userid, date=date)
        return func

    def __getattr__(self, name):
        try:
            return self._func_makeup(name)
        except Exception, e:
            raise KeyError, "'%s' maybe not defined, message: %s" % (name,e.message)



class auconfig():
    DATETIME_FORMAT     = dau_conf.DATETIME_FORMAT
    DATE_FORMAT         = dau_conf.DATE_FORMAT
    MONTH_FORMAT        = dau_conf.MONTH_FORMAT
    DATE_FORMAT_R       = dau_conf.DATE_FORMAT_R
    STD_OFFSET          = dau_conf.STD_OFFSET
    MAX_BITMAP_LENGTH   = dau_conf.MAX_BITMAP_LENGTH

    def __init__(self, dau_conf, filter_conf):
        self.dau_keys_conf    = dau_conf
        self.filter_keys_conf = filter_conf

            
