import pandas as pd
import numpy as np
import re
import ipaddress

def read_log(filename):
    """
    Return Pandas dataframe
    
    <8>Oct 25 16:40:17 Company SPL:0|Sky Guard|Data Security|1.0| displayName=172.22.83.192 logonName= distinguishedName= department= sourceIp=172.22.83.192 domain= detectTime=2018-10-25 16:39:26 actionType=放行 policyName=默认策略 channelType=HTTP urlHostname=api.foxitreader.cn destinationUrl=http://api.foxitreader.cn/message/updateTime?tags=commontags&updateTime=f97b4dd4411cb2dfd00b1d8c7bd7479d1540224004060 destinationIp=54.222.129.144 port=80 categoryType=null/其他 riskType=安全 riskLevel=安全 isSecure=安全 threatType=无安全威胁 keyword= filename=updateTime fileType=不可识别的文件类型 clickCount=1 browseTime=0 deviceName=SWG-INLINE23 city=北京 country=中国 position=39.9289,116.3883
    <8>Oct 25 16:40:17 Company SPL:0|Sky Guard|Data Security|1.0| displayName=于江城 logonName=yujiangcheng distinguishedName=CN=于江城,OU=SPS,OU=BJRDC,OU=Staff,DC=Companymis,DC=com department= sourceIp=172.22.3.56 domain=Companymis.com detectTime=2018-10-25 16:39:26 actionType=放行 policyName=默认策略 channelType=HTTPS urlHostname=www.cnblogs.com destinationUrl=https://www.cnblogs.com/mvc/blog/HistoryToday.aspx?blogId=69521&blogApp=wdkshy&dateCreated=2016%2F2%2F2+16%3A57%3A00 destinationIp=101.37.97.51 port=443 categoryType=null/其他 riskType=安全 riskLevel=安全 isSecure=安全 threatType=无安全威胁 keyword= filename=HistoryToday.aspx fileType=不可识别的文件类型 clickCount=1 browseTime=0 deviceName=SWG-INLINE23 city=杭州 country=中国 position=30.2936,120.1614
    """

    pattern_head = re.compile('(<8>(?:[a-zA-Z]{3,4}) \d{1,2} \d\d:\d\d:\d\d) (.*)')

    sers = []
    #for line in test_string.split('\n'):
    #the log is utf-8 format
    #python2.7 for line in open(filename, 'r'):
    #python3.7 requires encoding parameter
    for line in open(filename, mode="r", encoding="utf-8"):
        ret = re.match(pattern_head, line)
        if not ret:
            # skip the empty lines
            continue

        # Extract Groups
        time, key_values = ret.groups()

        dict = {}
        k = ''
        for token in key_values.split():
            #print(token)
            # if there is no '=', assign the value back to previous key
            if token.find("=") == -1:
                if len(k) > 0: # skip those without key
                    dict[k] = dict[k] + ' ' + token
                    #print(k, dict[k])
            else:    
                k, v = token.split('=', 1)
                dict[k] = v

        ser = pd.Series(dict)
        # time starts with <8>
        ser['log_time'] = time[3:]
        sers.append(ser)

    print('total row read: ', len(sers))
    df = pd.concat(sers, axis=1).T
    return df

# SWG
def create_source_login (row, domain, login):
    str = ''
    if len(row[domain]) > 0:
        if len(row[login]) > 0:
            str = row[domain] + "\\" + row[login]
    elif row[login].find('\\') != -1:
        str = row[login]
    return str

def convert_ip_to_int (row, col):
    if row[col].find('.') != -1:
    #    parts = row['sourceIp'].split('.')
    #    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        #return int(ipaddress.IPv4Address(unicode(row[col])))
        return int(ipaddress.IPv4Address(row[col]))
    return 0

# DLP
def find_path (row, full, file):
    if len(row[full]) > 0 and len(row[file]) > 0:
        pos = row[full].rfind(row[file])
        if pos != -1:
            return row[full][0:pos]
    
    return row[full]

def get_dayofweek (row, col):
    time = pd.to_datetime(row[col])
    return time.dayofweek

def get_timeofday (row, col):
    t = pd.to_datetime(row[col])
    return (t.hour*60 + t.minute)*60 + t.second

# Now, read logs and parse
dfSWG = read_log("Syslog - SWG.txt")
dfDLP = read_log("Syslog - DLP.txt")

# digitize textual data for SWG logs
# todo: save id mapping into file for future use
dfSWG['source.login'] = dfSWG.apply(lambda x: create_source_login(x, 'domain', 'logonName'), axis=1)
dfSWG['source.login.id'] = dfSWG.groupby(['source.login']).ngroup()
dfSWG['source.ip'] = dfSWG.apply(lambda x: convert_ip_to_int(x, 'sourceIp'), axis=1)
dfSWG['action.id'] = dfSWG.groupby(['actionType']).ngroup()
dfSWG['channelType.id'] = dfSWG.groupby(['channelType']).ngroup()
dfSWG['urlHostname.id'] = dfSWG.groupby(['urlHostname']).ngroup()
dfSWG['destination.ip'] = dfSWG.apply(lambda x: convert_ip_to_int(x, 'destinationIp'), axis=1)
dfSWG['filename.id'] = dfSWG.groupby(['filename']).ngroup()
dfSWG['fileType.id'] = dfSWG.groupby(['fileType']).ngroup()
dfSWG['categoryType.id'] = dfSWG.groupby(['categoryType']).ngroup()
dfSWG['detectTime.dayofweek'] = dfSWG.apply(lambda x: get_dayofweek(x, 'detectTime'), axis=1)
dfSWG['detectTime.timeofday'] = dfSWG.apply(lambda x: get_timeofday(x, 'detectTime'), axis=1)

#Below are useful fields for ML training
#dfSWG[['source.login', 'source.login.id', 'source.ip', 'destination.ip']]
#dfSWG[['actionType', 'action.id', 'channelType', 'channelType.id']]
#dfSWG[['urlHostname', 'urlHostname.id', 'filename', 'filename.id', 'categoryType', 'categoryType.id']]
#dfSWG[['detectTime', 'detectTime.dayofweek', 'detectTime.timeofday']]
#dfSWG[['clickCount', 'browseTime']]

# digitize textual data for DLP logs
# todo: save id mapping into file for future use
dfDLP['source.login'] = dfDLP.apply(lambda x: create_source_login(x, 'source.domain', 'source.logonName'), axis=1)
dfDLP['source.login.id'] = dfDLP.groupby(['source.login']).ngroup()
dfDLP['source.ip'] = dfDLP.apply(lambda x: convert_ip_to_int(x, 'source.ip'), axis=1)
dfDLP['action.id'] = dfDLP.groupby(['action']).ngroup()
dfDLP['channel.id'] = dfDLP.groupby(['channel']).ngroup()
dfDLP['details.path'] = dfDLP.apply(lambda x: find_path(x, 'details', 'fileNames'), axis=1)
dfDLP['details.path.id'] = dfDLP.groupby(['details.path']).ngroup()
dfDLP['fileNames.id'] = dfDLP.groupby(['fileNames']).ngroup()
dfDLP['detectTime.dayofweek'] = dfDLP.apply(lambda x: get_dayofweek(x, 'detectTime'), axis=1)
dfDLP['detectTime.timeofday'] = dfDLP.apply(lambda x: get_timeofday(x, 'detectTime'), axis=1)

#Below are useful fields for ML training
#dfDLP[['source.login', 'source.login.id', 'source.ip']]
#dfDLP[['action', 'action.id', 'channel', 'channel.id']]
#dfDLP[['details', 'fileNames', 'details.path', 'details.path.id', 'fileNames.id']]
#dfDLP[['detectTime', 'detectTime.dayofweek', 'detectTime.timeofday']]
#dfDLP[['transactionSize']]

#finally save to csv file
dfSWG.to_csv("Syslog - SWG.csv")
dfDLP.to_csv("Syslog - DLP.csv")

#testing: load from csv file
dfSWG = pd.read_csv("Syslog - SWG.csv")
dfDLP = pd.read_csv("Syslog - DLP.csv")
