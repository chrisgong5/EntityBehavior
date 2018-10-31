import pandas as pd
import numpy as np
import re

def read_log(filename):
    """
    Return Pandas dataframe
    
    <8>Oct 25 16:40:17 Company SPL:0|Sky Guard|Data Security|1.0| displayName=172.22.83.192 logonName= distinguishedName= department= sourceIp=172.22.83.192 domain= detectTime=2018-10-25 16:39:26 actionType=放行 policyName=默认策略 channelType=HTTP urlHostname=api.foxitreader.cn destinationUrl=http://api.foxitreader.cn/message/updateTime?tags=commontags&updateTime=f97b4dd4411cb2dfd00b1d8c7bd7479d1540224004060 destinationIp=54.222.129.144 port=80 categoryType=null/其他 riskType=安全 riskLevel=安全 isSecure=安全 threatType=无安全威胁 keyword= filename=updateTime fileType=不可识别的文件类型 clickCount=1 browseTime=0 deviceName=SWG-INLINE23 city=北京 country=中国 position=39.9289,116.3883
    <8>Oct 25 16:40:17 Company SPL:0|Sky Guard|Data Security|1.0| displayName=于江城 logonName=yujiangcheng distinguishedName=CN=于江城,OU=SPS,OU=BJRDC,OU=Staff,DC=Companymis,DC=com department= sourceIp=172.22.3.56 domain=Companymis.com detectTime=2018-10-25 16:39:26 actionType=放行 policyName=默认策略 channelType=HTTPS urlHostname=www.cnblogs.com destinationUrl=https://www.cnblogs.com/mvc/blog/HistoryToday.aspx?blogId=69521&blogApp=wdkshy&dateCreated=2016%2F2%2F2+16%3A57%3A00 destinationIp=101.37.97.51 port=443 categoryType=null/其他 riskType=安全 riskLevel=安全 isSecure=安全 threatType=无安全威胁 keyword= filename=HistoryToday.aspx fileType=不可识别的文件类型 clickCount=1 browseTime=0 deviceName=SWG-INLINE23 city=杭州 country=中国 position=30.2936,120.1614
    """

    pattern_head = re.compile('(<8>(?:[a-zA-Z]{3,4}) \d{1,2} \d\d:\d\d:\d\d) (.*)')

    sers = []
    #for line in test_string.split('\n'):
    for line in open(filename, 'r'):
        ret = re.match(pattern_head, line)
        if not ret:
            # skip the empty lines
            continue

        # Extract Groups
        time, key_values = ret.groups()

        dict = {}
        k = ''
        for token in key_values.split():
            #print token
            # if there is no '=', assign the value back to previous key
            if token.find("=") == -1:
                if len(k) > 0: # skip those without key
                    dict[k] = dict[k] + ' ' + token
                    #print k, dict[k]
            else:    
                k, v = token.split('=', 1)
                dict[k] = v

        ser = pd.Series(dict)
        # time starts with <8>
        ser['log_time'] = time[3:]
        sers.append(ser)

    #print 'total row: ', len(sers)
    df = pd.concat(sers, axis=1).T
    return df
 
 # examples
# dfSWG = read_log('Syslog - SWG.txt')
# dfDLP = read_log('Syslog - DLP.txt')
