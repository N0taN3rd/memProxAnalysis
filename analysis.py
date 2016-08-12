import json
from collections import Counter

from pywbCanonicalize import canonicalize, unsurt
from urllib.parse import urlparse
from operator import add
from functional import seq
import glob
from datetime import datetime
import arrow
import pytz
import plotly
from plotly.graph_objs import Scatter, Layout



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
        self.purl = urlparse(self.url)
        can = canonicalize(self.url).split(')/')
        self.domainc = can[0]
        self.domain = unsurt('%s%s' % (can[0], ')/'))
        self.pathc = can[1]
        self.hash = jdic['hash']
        self.mementoCount = jdic['mementoCount']

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
        return '%s %s %d\n'%(self.url,self.tstamp.humanize(),self.mcount)

    def __repr__(self):
        return self.__str__()



def wtf(x):
    print(x)
    return x


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

if __name__ == '__main__':
    c = Counter()
    for it in glob.glob('timemaps/*/*404-timemap.txt'):
        c[it.split('/')[1]] += 1
    print(c)


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
