import json
import pickle
import statistics
from collections import Counter
from collections import defaultdict
import math

from pywbCanonicalize import canonicalize, unsurt
from urllib.parse import urlparse
from operator import add
from functional import seq
import glob
from datetime import datetime
import arrow
import pytz
import plotly
from plotly.graph_objs import Scatter, Layout, Bar
import plotly.graph_objs as go

import requests


def to_dbentry(jdict):
    return DBEntry(jdict)


class DBEntry(object):
    """
    :type url: str
    :type hash: str
    :type domain: str
    :type path: str
    :type mementoCount: list[dict]
    """

    def __init__(self, jdic):
        self.url = jdic['url']
        can = canonicalize(self.url).split(')/')
        self.domainc = can[0]
        self.domain = unsurt('%s%s' % (can[0], ')/'))
        self.pathc = can[1]
        self.hash = jdic['hash']
        self.mementoCount = self.parseMCount(jdic['mementoCount'])

    def parseMCount(self, mCount):
        newList = []
        for mc in mCount:
            # print(mc)
            if isinstance(mc['date'], dict):
                continue
            print(mc['date'])
            try:
                mc['date'] = arrow.get(str(mc['date']), 'YYYYMMDDHHmmss').to('US/Eastern').format('YYYYMMDDHHmmss')
            except Exception:
                mc['date'] = arrow.get(str(mc['date'])).to('US/Eastern').format('YYYYMMDDHHmmss')
            newList.append(mc)
        return newList

    def find(self, date):
        for it in self.mementoCount:
            if it['date'] == date:
                print('found count', it['count'])
                return int(it['count'])
        if len(self.mementoCount) > 0:
            return math.ceil(statistics.mean(map(lambda x: int(x['count']), self.mementoCount)))
        else:
            return 0

    def to_dict(self):
        print("dbEntry to_dict")
        return {"url": self.url, "hash": self.hash, "mementoCount": self.mementoCount}

    def __str__(self):
        return '%s: %d' % (self.url, len(self.mementoCount))


class LogEntry(object):
    def __init__(self, jdic):
        self.message = jdic['message']
        m = self.message.replace('got timemap request url:count, ', '')
        self.url = m.replace(m[m.rfind(':'):], '')
        can = canonicalize(self.url).split(')/')
        self.domain = unsurt('%s%s' % (can[0], ')/'))
        self.mcount = int(m[m.rfind(':'):].replace(':', ''))
        self.tstamp = arrow.get(jdic['timestamp']).to('US/Eastern')

    def __str__(self):
        return '%s %s %d\n' % (self.url, self.tstamp.humanize(), self.mcount)

    def __repr__(self):
        return self.__str__()


def wtf(x):
    print(x)
    return x


def get_dbEntries():
    dbEntries = []  # type: list[DBEntry]
    with open('latest/currentPdata/dbs/url-hash-count.db', 'r') as dbIn:
        for it in map(lambda l: l.rstrip("\n"), dbIn):
            jdict = json.loads(it, encoding='utf8')
            dbEntries.append(DBEntry(jdict))
    urlToHash = seq(dbEntries) \
        .map(lambda e: (e.hash, e)) \
        .to_dict()
    return urlToHash


def db():
    dbEntries = []  # type: list[DBEntry]
    with open('url-hash-count.db', 'r') as dbIn:
        for it in map(lambda l: l.rstrip("\n"), dbIn):
            jdict = json.loads(it, encoding='utf8')
            dbEntries.append(DBEntry(jdict))

    domains = seq(dbEntries) \
        .map(lambda e: (e.domain, 1)) \
        .reduce_by_key(add) \
        .to_dict()
    for d, des in sorted(domains.items(), key=lambda x: x[1], reverse=True):
        print(d, des)

    urlToHash = seq(dbEntries) \
        .map(lambda e: (e.hash, e.url)) \
        .distinct() \
        .to_dict()
    for hash, url in urlToHash.items():
        print(hash, url)


def date_breakDown():
    logs = []
    with open('infos.log', 'r') as lin:
        for it in map(lambda l: json.loads(l.rstrip("\n"), encoding='utf8'), lin):
            # print(it)
            le = LogEntry(it)
            logs.append(le)

    byDay = seq(logs) \
        .group_by(lambda l: l.tstamp.day).to_dict()
    x = []
    y = []
    text = []
    for day, dg in byDay.items():
        print(day)
        for it in sorted(dg, key=lambda le: le.tstamp.time()):
            # print(it.url,it.tstamp.format('h:mm:ss a'),it.mcount)
            x.append(it.tstamp.datetime)
            y.append(it.mcount)
            text.append(it.domain)

    layout = dict(
        hovermode='closest',
        title='Memgator Access Timeline',
        xaxis=dict(
            rangeselector=dict(
                buttons=list([
                    dict(count=1,
                         label='1d',
                         step='day',
                         stepmode='todate'),
                    dict(count=1,
                         label='1hr',
                         step='hour',
                         stepmode='backwards'),
                    dict(count=5,
                         label='5hr',
                         step='hour',
                         stepmode='backwards'),
                    dict(step='all')
                ])
            ),
            rangeslider=dict(),
            type='date'
        )
    )

    data = [
        Scatter(
            x=x,
            y=y,
            text=text,
            mode='markers'
        )
    ]
    fig = dict(data=data, layout=layout)
    plotly.offline.plot(fig)


def deserialize(obj):
    print(obj)
    return {"hi": "hello"}


def serialize_ips():
    ips = {}  # type: dict[str,UniqueIp]
    for it in glob.glob('latest/currentPdata/timemaps/*/*timemap*'):
        try:
            print(it.split(':')[0].split('/')[4])
            # print(it.split(':')[3].split('-'))
            splited = it.split(':')[3].split('-')
            aIp = splited[0]
            uniqueIp = ips.get(aIp, None)
            if uniqueIp is None:
                ips[aIp] = UniqueIp(splited, it)
            else:
                ips[aIp].addAccess(splited, it)

        except IndexError as e:
            splited = it.split('-')
            aIp = splited[1]
            uniqueIp = ips.get(aIp, None)

            if uniqueIp is None:
                ips[aIp] = UniqueIp(splited, it)
            else:
                ips[aIp].addAccess(splited, it)
    dbEs = get_dbEntries()
    ipList = list(ips.values())
    for ip in ipList:
        ip.get_loc()
        for a in ip.accessDates:
            entry = dbEs[a.hash]
            a.url = entry.url
            a.mCount = entry.find(a.date.format('YYYYMMDDHHmmss'))

    with open('latest/ips.json', 'w') as ipOut:
        json.dump(ipList, ipOut, indent=1, default=lambda x: x.to_dict())


class LocInfo(object):
    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %s' % (self.country_code, self.city)

    def __init__(self, locDic):
        """
         :type longitude: decimal
         :type latitude: decimal
         :type zip_code: str
        :type metro_code: int
        :type region_code: str
        :type country_code: str
        :type country_name: str
        :type city: str
        :type region_name: str
        :type locDict: dict
        """
        self.longitude = locDic['longitude']
        self.latitude = locDic['latitude']
        self.zip_code = locDic['zip_code']
        self.metro_code = locDic['metro_code']
        self.region_code = locDic['region_code']
        self.country_code = locDic['country_code']
        self.country_name = locDic['country_name']
        self.city = locDic['city']
        self.region_name = locDic['region_name']
        self.locDict = locDic

    def to_dict(self):
        return self.locDict


class AccessInfo(object):
    """
    :type date: Arrow
    :type code: int
    :type mCount: int
    :type hash: str
    :type url: str
   """

    def __init__(self, splitted, full=None):
        self.date = None
        self.hash = None
        self.url = None
        self.mCount = -1
        self.code = -1
        if isinstance(splitted, dict):
            self.date = arrow.get(splitted['date'], 'YYYYMMDDHHmmss')
            self.code = str(splitted['code'])
            self.url = splitted['url']
            self.hash = splitted['hash']
            self.mCount = splitted["mCount"]
            self.can = canonicalize(self.url)
            self.domain = unsurt('%s%s' % (self.can.split(')/')[0], ')/'))
        else:
            self.hash = full.split(':')[0].split('/')[4].split('-')[0]
            if len(splitted) == 4:
                self.date = arrow.get(splitted[1], 'YYYYMMDDHHmmss').to('US/Eastern')
                self.code = splitted[2]
            else:
                self.date = arrow.get(splitted[2], 'YYYYMMDDHHmmss').to('US/Eastern')
                self.code = splitted[3]

    def to_dict(self):
        return {
            "date": self.date.format('YYYYMMDDHHmmss'),
            "code": self.code,
            "hash": self.hash,
            "url": self.url,
            "mCount": self.mCount
        }

    def report1(self):
        return self.domain, self.mCount, self.date

    def toString(self):
        return self.__str__()

    def __str__(self):
        return "%s code[%s] mementos[%s]" % (self.date.format('DD-hh:mm:ssA'), self.code, self.mCount)

    def __repr__(self):
        return self.__str__()


class UniqueIp(object):
    """
    :type ip: str
    :type accessDates: list[AccessInfo]
    :type locationInfo: LocInfo
    """

    def __init__(self, splitted, full=None):
        self.ip = ''
        self.accessDates = []
        self.locationInfo = None
        if isinstance(splitted, dict):
            self.ip = splitted['ip']
            self.locationInfo = LocInfo(splitted['locationInfo'])
            self.makeAccessInfos(splitted['accessDates'])
        else:
            self.accessDates.append(AccessInfo(splitted, full))
            if len(splitted) == 4:
                self.ip = splitted[0]
            else:
                self.ip = splitted[1]

    def __str__(self):
        return "%s %s" % (self.ip, ','.join(list(map(lambda x: x.toString(), self.accessDates))))

    def __repr__(self):
        return self.__str__()

    def makeAccessInfos(self, aiList):
        for aiDict in aiList:
            self.accessDates.append(AccessInfo(aiDict))

    def addAccess(self, splitted, full):
        self.accessDates.append(AccessInfo(splitted, full))

    def get_loc(self):
        response = requests.get('http://localhost:8080/json/%s' % self.ip)
        self.locationInfo = LocInfo(response.json())

    def report1(self):
        acg = seq(self.accessDates).group_by(lambda x: x.domain).to_list()
        return acg

    def to_dict(self):
        return {"ip": self.ip, "accessDates": self.accessDates, "locationInfo": self.locationInfo}

def get_ips():
    with open('latest/ips.json', 'r') as ipIn:
        ips = list(map(lambda x: UniqueIp(x), json.load(ipIn)))  # type: list[UniqueIp]
    return  ips

def do_ips_locations(serialize=False):
    if serialize:
        serialize_ips()
        return

    ips = get_ips()

    countriesG = seq(ips).group_by(lambda x: (x.locationInfo.longitude, x.locationInfo.latitude)).to_dict()
    lon = []
    latt = []
    texts = []
    codes = Counter()
    cntries = set()

    ccc = {}

    for (long, lat), grouped in countriesG.items():
        length = len(grouped)
        lon.append(long)
        latt.append(lat)
        uniqueDomains = 0
        uniqueIps = set()
        uniqueCities = set()
        totalVisits = 0
        if length <= 1:
            # print((long, lat), grouped[0].report1())
            report = grouped[0].report1()
            cntries.add(grouped[0].locationInfo.region_name)
            uniqueDomains = len(report)
            uniqueIps.add(grouped[0].ip)
            ccc[(long, lat)] = (grouped[0].locationInfo.region_name, grouped[0].locationInfo.country_name)
            uniqueCities.add(grouped[0].locationInfo.city)
            for domain, da in report:
                # print(domain)

                cs = seq(da).map(lambda a: (a.code, 1)).reduce_by_key(lambda a, b: a + b).to_dict()
                codes["404"] += cs.get('404', 0)
                codes["200"] += cs.get('200', 0)

                # da = sorted(da, key=lambda a: a.date)
                # minDate = da[0]
                # maxDate = da[-1]
                # print(minDate, maxDate)
                # print('----------------------------------------')

        else:
            # print((long,lat))
            for ui in grouped:
                # print(ui.report1())
                report = ui.report1()
                uniqueDomains += len(report)
                uniqueIps.add(ui.ip)
                uniqueCities.add(ui.locationInfo.city)
                ccc[(long, lat)] = (ui.locationInfo.region_name, ui.locationInfo.country_name)
                cntries.add(ui.locationInfo.country_name)
                for domain, da in report:
                    cs = seq(da).map(lambda a: (a.code, 1)).reduce_by_key(lambda a, b: a + b).to_dict()
                    codes["404"] += cs.get('404', 0)
                    codes["200"] += cs.get('200', 0)
                    # print(domain)
                    # da = sorted(da,key=lambda a: a.date)
                    # minDate = da[0]
                    # maxDate = da[-1]
                    #
                    #     print(maxDate.date.day - minDate.date.day)
                    # print('----------------------------------------')
        totalVisits = codes['404'] + codes['200']
        a, b = ccc[(long, lat)]
        text = "Where: %s-%s, City: %s, Unique ips: %d, Unique domains: %d, Total tm requests: %d, 404s: %d, " \
               "200s: %d" % \
               (a, b, '-'.join(list(uniqueCities)), len(uniqueIps), uniqueDomains, totalVisits, codes['404'],
                codes['200'])
        texts.append(text)
        print((long, lat), ccc[(long, lat)], list(uniqueCities)[0], "ips[%d]" % len(uniqueIps),
              "domains[%d]" % uniqueDomains, "total tm requests [%d]" % totalVisits, codes)
        print('----------------------------------------')
    print(cntries)
    d =dict(
        lon=lon,
        lat=latt,
        text=texts,
        countries=list(cntries)
    )
    pickle.dump(d, open("memgatorAccessPlotData.p", "wb"))


    data = [
        dict(
            # locationmode='country names',
            # locations=d['countries'],
            type='scattergeo',
            lon=d['lon'],
            lat=d['lat'],
            text=d['text'],
            mode='markers',
        )
    ]
    layout = dict(
        title='Memgator Access Locations',
        geo=dict(
            scope='world',
            projection=dict(type='robinson'),
            showland=True,
            landcolor="rgb(250, 250, 250)",
            # subunitcolor="rgb(217, 217, 217)",
            # countrycolor="rgb(217, 217, 217)",
            # countrywidth=0.5,
            # subunitwidth=0.5
        ),
    )

    fig = dict(data=data, layout=layout)
    plotly.offline.plot(fig, filename='memgator-access-locations.html', auto_open=False)

    # for a in it.accessDates:
    #     print(a.url,a.mCount)
    # for ip in ips.values():
    #     print(ip)

    # for ip in ips:
    #     print(ip)
    #     c[it.split('/')[1]] += 1
    # print(c)

def sanity():
    cities = pickle.load(open("memgatorCities.p", "rb"))  # type: dict[str,list[UniqueIp]]
    cC = {}
    us = {}
    all = []
    tc = 0
    for c, cg in cities.items():
        length = 0
        codes = Counter()
        for ui in cg:
            length += len(ui.accessDates)
            for ad in ui.accessDates:
                codes[ad.code] += 1
        print(c, length)
        if c in ['Norfolk', 'Chesapeake', 'Los Alamos', 'Portsmouth', 'Hampton']:
            us[c] = length, codes
        else:
            if c == '':
                c = 'Unknown'
            cC[c] = length, codes
        tc += length

    print(cC)
    print(us)

    totalText = []
    totalTextF = []
    totalTextT = []

    sanity = []
    x = []
    totalsC = []
    fourHundoCount = []
    twoHundoCount = []
    us2 = {}
    usName = ''
    usTCount = 0
    usf = 0
    ust = 0
    totalF = 0
    totalT = 0
    for city, (count, codes) in us.items():
        print(city, count, codes)
        usName += city + ' '
        usTCount += count
        usf += codes['404']
        totalF += codes['404']
        ust += codes['200']
        totalT += codes['200']

    print(usName.rstrip(), usf, ust)
    x.append("WSDL")
    totalText.append("%.2f%% of all requests" % ((float(usTCount) / float(tc)) * 100.0))
    sanity.append(((float(usTCount) / float(tc)) * 100.0))

    totalsC.append(usTCount)
    fourHundoCount.append(usf)
    twoHundoCount.append(ust)

    for city, (count, codes) in sorted(cC.items(), key=lambda x: x[0]):
        print(city, count, codes)
        x.append(city)
        totalText.append("%.2f%% of all requests" % ((float(count) / float(tc)) * 100.0))
        sanity.append(((float(count) / float(tc)) * 100.0))
        totalsC.append(count)
        totalF += codes['404']
        totalT += codes['200']
        fourHundoCount.append(codes['404'])
        twoHundoCount.append(codes['200'])

    print(sum(sanity))

    totalTextF.append("%.3f%% of all 404 responses" % ((float(usf) / float(tc)) * 100.0))
    totalTextT.append("%.3f%% of all 200 responses" % ((float(ust) / float(tc)) * 100.0))

    for (f, t) in zip(fourHundoCount, twoHundoCount):
        print(f, t, totalF, totalT, ((float(f) / float(totalF)) * 100.0), ((float(t) / float(tc)) * 100.0))
        totalTextF.append("%.3f%% of all requests" % ((float(f) / float(tc)) * 100.0))
        totalTextT.append("%.3f%% of all requests" % ((float(t) / float(tc)) * 100.0))
    print(sum(sanity))

if __name__ == '__main__':
    lines = []
    for it in glob.glob('/home/john/memproxData/tars/dbs*/*.db'):
        with open(it, 'r') as dbIn:
            for line in map(lambda l: l.rstrip("\n"), dbIn):
                lines.append(line)
    with open('combined.db','w') as out:
        for line in lines:
            out.write('%s\n'%line)
    # data = [
    #     dict(
    #         type='bar',
    #         x=x,
    #         text=totalText,
    #         y=totalsC,
    #         name='Total Requests',
    #         marker=dict(
    #             color='rgb(204,204,204)',
    #         ),
    #
    #     ),
    #     dict(
    #         type= 'bar',
    #         x=x,
    #         y=twoHundoCount,
    #         name='200 Responses',
    #         marker=dict(
    #             color='rgb(49,130,189)'
    #         ),
    #         text = totalTextT
    #
    #
    #     ),
    #     dict(
    #         type= 'bar',
    #         x=x,
    #         y=fourHundoCount,
    #         name='404 Responses',
    #         marker=dict(
    #             color='rgb(228,87,81)',
    #         ),
    #         text=totalTextF
    #     ),
    #
    # ]
    #
    # layout = dict(
    #     title="Memgator Timemap Request Breakdown by City",
    #     xaxis=dict(tickangle=-45, title='City Requests were made from'),
    #     yaxis=dict(title='Request/Response count'),
    #     barmode='group',
    #     margin=dict(
    #         l=150,
    #         r=50,
    #         b=100,
    #         t=100,
    #         pad=4
    #     ),
    # )
    #
    # # fig = dict(data=data, layout=layout)
    # fig = dict(data=data, layout=layout)
    # plotly.offline.plot(fig, filename='memgator-access-breakdown.html')


        # ips = get_ips()
    # cities = seq(ips).group_by(lambda _: _.locationInfo.city).to_dict()
    # pickle.dump(cities, open("memgatorCities.p", "wb"))
    # print(cities)

    # serialize_ips()
    # get_dbEntries()



    # plotly.offline.plot({
    #     "data": [
    #         Scatter(
    #             x=x,
    #             y=y,
    #             text=text,
    #             mode='markers'
    #         )
    #     ],
    #     "layout": Layout(title="hello world")
    # })



    # for dbe in map(lambda x: json.loads(x,object_hook=to_dbentry),dbIn):
    #     print(dbe)
