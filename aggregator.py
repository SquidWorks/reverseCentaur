import os
from subprocess import Popen, PIPE, STDOUT
import argparse
import operator
import time
import csv
import glob
import pandas as pd


parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Filename of the dir to read', required=True)
parser.add_argument('-wt', '--writeTcp', help='Filename of the csv to write', required=True)
parser.add_argument('-wd', '--writeDns', help='Filename of the csv to write', required=True)
parser.add_argument('-t', '--time', help='Time length to split by if desired', required=False, default='std')
parser.add_argument('-l', '--label', help='Label for dataset', required=True)
parser.add_argument('-d', '--dataset', help='Dataset name', required=True)
parser.add_argument('-o', '--owner', help='Owner name', required=True)
parser.add_argument('-a', '--append', help='If set, appends to existing csv', required=False, action='store_true')
parser.add_argument('-z', '--target', help='Record data for targeted IP address only', required=False)

args = vars(parser.parse_args())

start = time.time()

dirName = args['read']

label = args['label']
dataset = args['dataset']
owner = args['owner']
target = args['target']

outputCsvTcp = args['writeTcp']
outputCsvDns = args['writeDns']


timer = args['time']
string = ""
if args['time']:
    string += " -t " + args['time'] +" "
if args['target']:
    string += " -z " + args['target'] + " "



count = 1

allFiles = glob.glob(dirName+ "/*/*.bz2")

for i in allFiles:
    cmd = 'bzip2 -dk '+i
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)
    fileName = i.rsplit('.', 1)[:-1][0]
    #dirPath = i.rsplit('/', 1)[:-1][0]
    #print(dirPath)
    cmd = 'tshark -nr '+ fileName + ' -N -Y "(ip.addr== 10.1.70.20) and  (ip.addr!= 10.1.70.40 or ip.addr!= 10.1.70.41 or ip.addr!= 10.1.70.42 or ip.addr!= 10.1.70.43) and (! ldap or ! ftp or ! tpkt) and (dns or tcp)" -w temporary.pcap'
    print("****" + cmd)
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)
    cmd = "python pcapToTcpCsv.py -r temporary.pcap -w tempTcp.csv"
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    cmd = "python csvTcpToPandas.py -r tempTcp.csv -w "+ outputCsvTcp + " -l "+ label + " -d " + dataset + " -o " + owner + string
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)
    cmd = "python pcapToDnsCsv.py -r temporary.pcap -w tempDns.csv"
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)
    cmd = "python csvDnsToPandas.py -r tempDns.csv -w " + outputCsvDns + " -l "+ label + " -d " + dataset + " -o " + owner + string
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)
   # print("python remove temporary.pcap")
    print("python remove tempTcp.csv")
    print("python remove tempDns.csv")

end = time.time()
print(end - start)
