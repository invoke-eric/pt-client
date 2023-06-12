import pandas as pd
import argparse
import re
import sys
from passivetotal import analyzer


def concat_dataframes(df_list):
    concat_df = pd.concat(df_list)
    return(concat_df)

def get_domain_resolutions_df(domain):
    host = analyzer.Hostname(domain.strip())
    resolutions = host.resolutions
    records = resolutions.only_a_records.as_df
    return(records)

def get_IP_reverse_resolutions_df(ip_address):
    records = analyzer.IPAddress(ip_address.strip()).resolutions.only_a_records.as_df
    return(records)

def get_whois_df(domain):
    host = analyzer.Hostname(domain.strip())
    records = host.whois.as_df
    return(records)

def get_soa_df(domain):
    host = analyzer.Hostname(domain.strip())
    res_df = host.resolutions.as_df
    soa_df = res_df[(res_df["recordtype"] == 'SOA')]
    return(soa_df)

def get_cert_df(cert_sha1):
    certs = analyzer.ssl.CertificateField('sha1', cert_sha1).certificates
    hist = certs[0].iphistory
    hist_df = pd.DataFrame(hist)
    return(hist_df)

def get_ipinfo_df(ip_address):
    ip = analyzer.IPAddress(ip_address)
    ip_info_df = ip.summary.as_df
    return(ip_info_df)



ipregex = re.compile(r'(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?')
domainregex = re.compile(r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b')
sha1regex = re.compile(r'([0-9a-f]{40})')

def create_domainlist(input):
    domainlist = []
    for line in input:
        line = line.strip()

        match_domainregex = domainregex.match(line)

        if match_domainregex:
            domainlist.append(line)

        elif not match_domainregex:
            pass
    
    return(domainlist)

def create_iplist(input):
    iplist = []
    for line in input:
        line = line.strip()

        match_ipregex = ipregex.match(line)

        if match_ipregex:
            iplist.append(line)

        elif not match_ipregex:
            pass
    return(iplist)

def create_certlist(input):
    certlist = []
    for line in input:
        line = line.strip()

        match_sha1regex = sha1regex.match(line)

        if match_sha1regex:
            certlist.append(line)

        elif not match_sha1regex:
            pass
    
    return(certlist)

def write_csv(df, csv_path):
    df.to_csv(str(csv_path))

def main():
    analyzer.init()
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", nargs="?", action="store", help="OPTIONAL - name of file containing IOCs of interest; if not provided, reads from STDIN")

    parser.add_argument("--csv", "-c", action="store", help="output csv path prefix")
    parser.add_argument("--start", "-s", action="store", help="query start date")
    parser.add_argument("--end", "-e", action="store", help="query end date")
    parser.add_argument("--resolutions", "-r", action="store_true", help="return domain resolutions")
    parser.add_argument("--reverse", "-x", action="store_true", help="run reverse DNS query on IPs")
    parser.add_argument("--whois", "-w", action="store_true", help="retrieve WHOIS records")
    parser.add_argument("--soa", action="store_true", help="retrieve SOA records")
    parser.add_argument("--certificates", action="store_true", help="Retrieve IP history for certificates by SHA1 fingerprint")
    parser.add_argument("--ipinfo", "-i", action="store_true", help="Retrieve IP info for a list of IPs")
    args = parser.parse_args()

    if (args.input_file):
        with open(args.input_file, 'r') as file:
            domainlist = create_domainlist(file)
        with open(args.input_file, 'r') as file:
            iplist = create_iplist(file)
        with open(args.input_file, 'r') as file:
            certlist = create_certlist(file)
    else:
        data = sys.stdin.readlines()
        domainlist = create_domainlist(data)
        iplist = create_iplist(data)
        certlist = create_certlist(data)
        

    #filename = args.input_file

    #domainlist = create_domainlist(filename)
    
    if(args.start):
        if(args.end):
            analyzer.set_date_range(start=args.start, end=args.end)
        elif not args.end:
            analyzer.set_context(start=args.start)
    
    if(args.end and not args.start):
        analyzer.set_date_range(end=args.end)
    
    if(args.resolutions):
        df_list = []
        for d in domainlist:
            resolutions = get_domain_resolutions_df(d)
            df_list.append(resolutions)
        resolutions_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "resolutions.csv"
            write_csv(resolutions_df, path)
        else:
            write_csv(resolutions_df, "resolutions.csv")


    if(args.reverse):
        #iplist = create_iplist(filename)
        df_list = []
        for i in iplist:
            reverse = get_IP_reverse_resolutions_df(i)
            df_list.append(reverse)
        reverse_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "reverse.csv"
            write_csv(reverse_df, path)
        else:
            write_csv(reverse_df, "reverse.csv")

    if(args.whois):
        df_list = []
        for d in domainlist:
            whois = get_whois_df(d)
            df_list.append(whois)
        whois_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "whois.csv"
            write_csv(whois_df, path)
        else:
            write_csv(whois_df, "whois.csv")

    if(args.soa):
        df_list=[]
        for d in domainlist:
            soa = get_soa_df(d)
            df_list.append(soa)
        soa_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "soa.csv"
            write_csv(soa_df, path)
        else:
            write_csv(soa_df, "soa.csv")
    
    if(args.certificates):
        df_list = []
        for i in certlist:
            cert = get_cert_df(i)
            df_list.append(cert)
        cert_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "cert_iphistory.csv"
            write_csv(cert_df, path)
        else:
            write_csv(cert_df, "cert_iphistory.csv")
    
    if(args.ipinfo):
        df_list = []
        for i in iplist:
            ip_info_df = get_ipinfo_df(i)
            df_list.append(ip_info_df)
        result_df = concat_dataframes(df_list)

        if(args.csv):
            path = args.csv + "ipinfo.csv"
            write_csv(result_df, path)
        else:
            write_csv(result_df, "ipinfo.csv")


if __name__ == '__main__':
    main()