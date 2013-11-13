"""
crawler-detection1.0
Author : Nilani Algiriyage
Tested on Ubuntu 12.04 with python 2.7.3
A simple python script to identify and classify possible crawlers through analysis of web server log files 
"""
def crawler_detection():
    import glob
    import pandas as pd
    import apachelog, sys
    import numpy as np
    import re
    import csv
    from datetime import datetime
    import string
    import os
    import pandas
    from socket import gethostbyaddr 
    import subprocess   
    import io
    from bulkwhois.shadowserver import BulkWhoisShadowserver
    from pandas import read_csv
    import httpbl
    from dateutil import parser


    fformat = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
    
    p = apachelog.parser(fformat)
    log_list = []

    path = os.path.abspath("crawler-detection/Data/*.log")
    for file in glob.glob(path):
        with open(file,'r') as f:
            for line in f:
                try:
                    data = p.parse(line)
                except:
                    pass
                log_list.append(data)
    
    df = pd.DataFrame(log_list)
    
    df = df.rename(columns={'%>s': 'Status', '%b':'Bytes', 
                            '%h':'IP','%l':'UserName' ,'%r':'Request', '%t': 'Time', '%u':'UserID','%{Referer}i' : 'Referer', '%{User-Agent}i' : 'Agent'})     
    
    
    class color:
       PURPLE = '\033[95m'
       CYAN = '\033[96m'
       DARKCYAN = '\033[36m'
       BLUE = '\033[94m'
       GREEN = '\033[92m'
       YELLOW = '\033[93m'
       RED = '\033[91m'
       BOLD = '\033[1m'
       UNDERLINE = '\033[4m'
       END = '\033[0m'
       
    def parse(x):
        date, hh, mm, ss = x.split(':')
        dd, mo, yyyy = date.split('/')
        return parser.parse("%s %s %s %s:%s:%s" % (yyyy,mo,dd,hh,mm,ss))
    
    df['Time'] = df['Time'].apply(lambda x:x[1:-7])
    df['Time'] = pd.DataFrame(dict(time = pd.to_datetime(map(parse,df['Time']))))   
    g = df.groupby(['IP', 'Agent'])
    
    """
    Generate user-sessions based on IP,user-agent and 30 minute timestamp
    """
    
    df['session_number'] = g['Time'].apply(lambda s: (s - s.shift(1) > pd.offsets.Minute(30).nanos).fillna(0).cumsum(skipna=False))
    df1 = df.set_index(['IP', 'Agent', 'session_number'])
    g1 = df.groupby(['IP', 'Agent', 'session_number'])
    df1['session'] = g1.apply(lambda x: 1).cumsum()
    NoOfSessions = len(df1.groupby('session')) 
    print color.BOLD+'\n1.0 Total No of Sessions : ' +color.END+ str(NoOfSessions)
    
    df2 = pd.DataFrame(df1.reset_index())
    df2 = df2[~df2['Agent'].str.contains("pingdom|panopta|nagios", na=False)]
    df3 = pd.DataFrame({'count' : df2.groupby( ["Request","session"] ).size()}).reset_index()
    robotssessions = df3[df3['Request'] == 'GET /robots.txt HTTP/1.1']['session'].unique()
    robotsaccessed = pd.DataFrame(df2[df2['session'].isin(robotssessions)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False))
    print color.BOLD+'\n2.0 No of sessions accessed "robots.txt" : '+color.END+str(len(robotsaccessed))
    
    """
    Write all robots.txt accessed HTTP requests in to a csv file
    """
    
    robotsaccessed.to_csv('robots.txt Accessed', sep=',' , header=False , index=False)
    
 
    """
    Data related to accessing hidden links,hidden links are implemented as 
    link1.html,link2.html,link2.html
    """
    hiddenlinkType1 = df3[(df3['Request'].str.contains("link1.html", na=False))]['session'].unique()
    hiddenlinkType2 = df3[(df3['Request'].str.contains("link2.html", na=False))]['session'].unique()
    hiddenlinkType3 = df3[(df3['Request'].str.contains("link3.html", na=False))]['session'].unique()
    
    
    hiddenlinkaccessedType1 = pd.DataFrame(df2[df2['session'].isin(hiddenlinkType1)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False))
    hiddenlinkaccessedType2 = pd.DataFrame(df2[df2['session'].isin(hiddenlinkType2)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False))
    hiddenlinkaccessedType3 = pd.DataFrame(df2[df2['session'].isin(hiddenlinkType3)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False))
    
    
    hiddenlinksessions = df3[(df3['Request'].str.contains("link1", na=False))]['session'].unique()
    hiddenlinkaccessed = pd.DataFrame(df2[df2['session'].isin(hiddenlinksessions)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False))
    
    print color.BOLD+'\n3.0 No of sessions accessed any type of hidden link : '+color.END+str(len(hiddenlinkaccessed))
    hiddenlinkaccessed.to_csv('hiddenlinks Accessed', sep=',' , header=False , index=False)
    
    
    hiddenlinkaccessedip = hiddenlinkaccessed.IP.unique()
    hiddenlinkaccessed2 = pd.DataFrame(df2[df2['IP'].isin(hiddenlinkaccessedip)][['IP','Agent','session']])
    
    """
    Hit count analysis
    """
    hitcount = pd.DataFrame({'count' : df2.groupby( ["session","IP"] ).size()}).reset_index()
    hitcountgreater = pd.DataFrame(hitcount[hitcount['count']>50])
    hitcountgreatersessions = hitcountgreater.session.unique()
    dfhitcountgreater = df2[df2['session'].isin(hitcountgreatersessions)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False)
    hitsswithagent = pd.DataFrame(pd.merge(hitcountgreater,dfhitcountgreater, how='outer'))
    
    """
    Threshold value for hit count is considered as 50
    """
    
    df4 = pd.DataFrame({'count' : df2.groupby( ["Referer","session"] ).size()}).reset_index()
    blanksessions = pd.DataFrame(df2[df2['Referer'] == '-'][['IP','Agent','Referer','session']])
    dfx = pd.DataFrame({'count' : blanksessions.groupby(["session","IP"]).size()}).reset_index()
    
    """
    Threshold value for blank referrer hit count is considered as 50
    """
    
    thresh2 = pd.DataFrame(dfx[dfx['count']>50])
    thresh2Sessions = thresh2.session.unique()
    blankreferrer = pd.DataFrame(df2[df2['session'].isin(thresh2Sessions)][['IP','Agent','Referer','session']].drop_duplicates(cols='session', take_last=False))
    dfblankreferrer = pd.DataFrame(pd.merge(thresh2,blankreferrer, how='outer'))
    
    
    """
    IDENTIFIER...
    All possible web crawlers
    """
    merged1 = pd.merge(robotsaccessed,hiddenlinkaccessed, how='outer')
    merged3 = pd.merge(merged1,hitsswithagent, how='outer')
    merged4 = pd.merge(merged3,dfblankreferrer, how='outer')
    dfmeged = pd.DataFrame(merged4)
    
    dfmeged.drop_duplicates(cols='session', take_last=False).to_csv('PossibleCrawlers', sep=',' , header=False , index=False)
    print color.BOLD+'\n4.0 No of All Possible Web crawler Sessions : '+color.END+str(len(dfmeged.drop_duplicates(cols='session', take_last=False)))
    dfmeged.drop_duplicates(cols='IP', take_last=False).to_csv('PossibleCrawlers2', sep=',' , header=False , index=False)
    
    """
    CHECKER...
    """
    
    print color.BOLD+'\n5.0 Single IP using multiple User Agents : '+color.END
    useragents = pd.DataFrame(dfmeged.groupby(['IP','Agent']).size().reset_index().groupby('IP').size()[50:80])
    useragents = useragents.reset_index() 
    useragents.columns = ['IP','AgentCount']
    useragentscountgreater = pd.DataFrame(useragents[useragents['AgentCount']>=2])
    mergeMultipleUA = pd.merge(dfmeged,useragentscountgreater, how='inner')
    if mergeMultipleUA.empty:
        print('No Results Found!')
    else:
        print mergeMultipleUA[0:25]
        
        
    multiuseragentIPs = mergeMultipleUA.IP.unique()
    
    """
    Violation of RFC2616 Blank user-agents
    """
    
    blankagents = pd.DataFrame(dfmeged[dfmeged['Agent'] == '-'][['IP','Agent','Referer','session']])
    hiddenlinksessions = df3[(df3['Request'].str.contains("aboutnic", na=False))]['session'].unique()
    hiddenlinkaccessed = pd.DataFrame(df2[df2['session'].isin(hiddenlinksessions)][['IP','Request','Agent','session']])
    
    
    bulk_whois = BulkWhoisShadowserver()
    f = open('PossibleCrawlers')
    lines = f.readlines()
    
    
    """
    "whois" verification of user-agents
    """
    ip = []
    myfile = open('whois', 'w')
    
    for line in lines:
        ip.append(line.split(',')[0])
        
    records = bulk_whois.lookup_ips(ip)
    
    xy = []
    for record in records:
        kk= "\t".join([records[record]["ip"], records[record]["asn"],
                        records[record]["as_name"], records[record]["cc"]])
        
        myfile.write(records[record]["ip"]+','+records[record]["as_name"]+'\n')
    myfile.close()
    
    
    foo = open('whois','r')
    lines = foo.readlines()
    verifiedlist = []
    for line in lines:
        ip = line.split(',')[0]
        desc = line.split(',')[1]
    dfverified = read_csv('whois')
    dfverified.columns = ['IP','Verified']
    test = pd.merge(dfverified,dfmeged, how='inner')
    dfmerged = pd.DataFrame(test)
    
    
    """
    "known" crawlers
    """
    goodcrawlers = dfmerged[dfmerged['Verified'].str.contains("YANDEX|MICROSOFT|GOOGLE|SOFTLAYER|CNNIC-BAIDU|CHINANET-IDC-BJ|CHINA169", na=False)]
    dfGoodCrawlers = pd.DataFrame(goodcrawlers)
    print color.BOLD+'\n6.0 No of unique "known" crawler sessions(only first 25) : '+color.END+str(len(dfGoodCrawlers.drop_duplicates(cols='session', take_last=False)))
    dfGoodCrawlers['Verified'] = dfGoodCrawlers['Verified'].fillna('Not Found')
    dfGoodCrawlers.to_csv('Known Crawlers', sep=',' , header=False , index=False)
    
    
    
    notGoodcrawlers = dfmerged[~dfmerged['Verified'].str.contains("YANDEX|MICROSOFT|GOOGLE|SOFTLAYER|CNNIC-BAIDU|CHINANET-IDC-BJ|CHINA169", na=False)]
    dfNotGoodCrawlers = pd.DataFrame(notGoodcrawlers)
    print color.BOLD+'\n7.0 Fake use of a "known" crawler user-agent string(only first 25) : '+color.END
    dfNotGoodCrawlers2 = dfNotGoodCrawlers
    dfNotGoodCrawlers2 = dfNotGoodCrawlers2.dropna()
    dfNotGoodCrawlers3 = dfNotGoodCrawlers2[dfNotGoodCrawlers2['Agent'].str.contains("yandex|msn|google|baidu|pingdom|Google|ahrefs", na=False)]
    if dfNotGoodCrawlers3.empty:
        print('No Results Found!') 
    else:
        print dfNotGoodCrawlers3[0:25]
    
    dfNotGoodCrawlers.drop_duplicates(cols='IP', take_last=False).to_csv('Not Known Crawlers', sep=' ', header=False , index=False)
    
    
    """
    Get IPs of faked user agents
    """
    
    fakeuseragent = dfNotGoodCrawlers[dfNotGoodCrawlers['Agent'].str.contains("yandex|msn|google|baidu|pingdom|Google|ahrefs", na=False)][['IP','Agent','session']]
    fakeuseragentS = fakeuseragent.session
    allip = open('Not Known Crawlers').readlines()
    fo = open('blacklistIps','w')
    
    """
    Check for malicious crawlers in abuseat and spamhaus databases
    """
    for line in allip:
        ips = line.strip().split(' ')[0]
        ip = str(ips).split('.')
        rev = '%s.%s.%s.%s' % (ip[3],ip[2],ip[1],ip[0])
        spamdbs = ['.cbl.abuseat.org', '.zen.spamhaus.org']
        
        for db in spamdbs:
            if db == '.pbl.spamhaus.org':
                break            
            p = subprocess.Popen(["dig", "+short", rev+db], stdout=subprocess.PIPE)
            output, err = p.communicate()     
            if output != "":
                fo.write(db+','+ips+'\n')
    
    
    """
    Project honeypot databse check
    """
    key = 'ornrkapawxsj'
    bl = httpbl.HttpBL(key)
    res = []
    honeypotips = []
    for line in allip:
        ips = line.strip().split(' ')[0]
        response = bl.query(ips)
        if response['threat_score']>50:
            res.extend((ips,response['threat_score'],response['type']))
            honeypotips.append(ips)
    fo.close()
    
    myfile = open('honeypot', 'w')
    wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
    wr.writerow(honeypotips)   
    
    if os.path.getsize('honeypot') > 0:
        print honeypotips
        print color.BOLD+'\n8.0 Honeypot Project Crawlers\n'+color.END
        print dfNotGoodCrawlers[dfNotGoodCrawlers['IP'].isin(honeypotips)][['IP','Agent','Verified']].drop_duplicates(cols='IP', take_last=False)
    
    if os.path.getsize('blacklistIps') > 0:
    
        dfMalicious = pd.read_csv('blacklistIps', sep=',', header=None)
        dfMalicious.columns = ['BlacklistDatabase','IP']
        joinedMalicious = dfMalicious.groupby('IP', ).agg(lambda x: ', '.join(x.values))
        dfMaliciousNew = pd.DataFrame(joinedMalicious)
        dfMaliciousNew = dfMaliciousNew.reset_index()
    
        malIP = dfMaliciousNew.IP
        dfdata = dfNotGoodCrawlers[dfNotGoodCrawlers['IP'].isin(malIP)][['IP','Agent','Verified']].drop_duplicates(cols='IP', take_last=False)
        dfMaliciousCrawlers1 = pd.DataFrame(dfdata)
        test = pd.merge(dfMaliciousCrawlers1,dfMaliciousNew, how='inner')
    
        dfMaliciousCrawlers2 = pd.DataFrame(test)
        dfMaliciousCrawlers2 = dfMaliciousCrawlers2.reset_index()
        
        dfMaliciousCrawlersIPs = dfMaliciousCrawlers2.IP.unique()
        dfMaliciousCrawlersSessions = dfNotGoodCrawlers[dfNotGoodCrawlers['IP'].isin(dfMaliciousCrawlersIPs)][['session']].drop_duplicates(cols='session', take_last=False)
        
        blacklistip1 = pd.DataFrame(dfMaliciousCrawlersSessions)
        blacklistip1.columns = ['session']
        blacklistip2 = pd.DataFrame(fakeuseragentS)
        blacklistip2.columns = ['session']
    
        multiuseragentS = dfNotGoodCrawlers[dfNotGoodCrawlers['IP'].isin(multiuseragentIPs)][['session']].drop_duplicates(cols='session', take_last=False)
    
        blacklistip3 = pd.DataFrame(multiuseragentS)
        blacklistip3.columns = ['session']
        
    
        blacklistip5 = pd.DataFrame(blankagents.session.unique())
        blacklistip5.columns = ['session']
        
        blacklistip6 = pd.DataFrame(hiddenlinkaccessedType3.session.unique())
        blacklistip6.columns = ['session']
    
        
        IPmerge1 =  pd.merge(blacklistip1,blacklistip2, how='outer')
        IPmerge2 = pd.merge(IPmerge1,blacklistip3, how='outer')
        IPmerge4 = pd.merge(IPmerge2,blacklistip5, how='outer')
    
        anomalousIPS = pd.merge(IPmerge4,blacklistip6, how='outer')
        anomalousips = anomalousIPS.session
    
        """
        Suspicious crawler patterns
        """    
        dfanodata = dfNotGoodCrawlers[dfNotGoodCrawlers['session'].isin(anomalousips)][['IP','Agent','Verified','session']].drop_duplicates(cols='session', take_last=False)
        dfanomalousCrawlers = pd.DataFrame(dfanodata)
        anomaloussessions = dfanomalousCrawlers.session
        dfanomalousCrawlers.to_csv('Suspicious Crawlers', sep=',' , header=False , index=False)
        print color.BOLD+'\n9.0 No of "suspicious" crawler sessions : '+color.END+str(len(dfanomalousCrawlers.drop_duplicates(cols='session', take_last=False)))
    
        """
        Other crawler patterns
        """    
        other = dfNotGoodCrawlers[~dfNotGoodCrawlers['session'].isin(anomaloussessions)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False)
        dfOther = pd.DataFrame(other)
        print color.BOLD+'\n10.0 No of "other" crawler sessions : '+color.END +str(len(dfOther.drop_duplicates(cols='session', take_last=False)))
        dfOther.to_csv('Other Crawlers', sep=',' , header=False , index=False)
    
    else:
        
        blacklistip2 = pd.DataFrame(fakeuseragentIPs)
        blacklistip2.columns = ['IP']
        
        blacklistip3 = pd.DataFrame(multiuseragentIPs)
        blacklistip3.columns = ['IP']
        
        blacklistip5 = pd.DataFrame(blankagents.IP.unique())
        blacklistip5.columns = ['IP']
    
        IPmerge1 =  pd.merge(blacklistip2,blacklistip3, how='outer')
        anomalousIPS = pd.merge(IPmerge1,blacklistip5, how='outer')
        
    
        """
        Suspicious crawler patterns
        """    
        dfanodata = dfNotGoodCrawlers[dfNotGoodCrawlers['session'].isin(anomalousips)][['IP','Agent','Verified','session']].drop_duplicates(cols='session', take_last=False)
        dfanomalousCrawlers = pd.DataFrame(dfanodata)
        anomaloussessions = dfanomalousCrawlers.session
        dfanomalousCrawlers.to_csv('Suspicious Crawlers', sep=',' , header=False , index=False)
        print color.BOLD+'\n9.0 No of "suspicious" crawler sessions : '+color.END +str(len(dfanomalousCrawlers.drop_duplicates(cols='session', take_last=False)))
        print dfanomalousCrawlers[0:25]
            
        
        """
        Other crawler patterns
        """    
        other = dfNotGoodCrawlers[~dfNotGoodCrawlers['session'].isin(anomaloussessions)][['IP','Agent','session']].drop_duplicates(cols='session', take_last=False)
        dfOther = pd.DataFrame(other)
        print color.BOLD+'\n10.0 No of "other" crawler sessions : '+ color.END + (len(dfOther.drop_duplicates(cols='session', take_last=False)))
        dfOther.to_csv('Other Crawlers', sep=',' , header=False , index=False)
