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
parser.add_argument('-w', '--write', help='Filename of the csv to write', required=True)
parser.add_argument('-t', '--time', help='Time length to split by if desired', required=False, default='std')
parser.add_argument('-l', '--label', help='Label for dataset', required=True)
parser.add_argument('-d', '--dataset', help='Dataset name', required=True)
parser.add_argument('-o', '--owner', help='Owner name', required=True)

parser.add_argument('-m', '--malware', help='Record data for targeted IP address only', required=False)
parser.add_argument('-p', '--protocol', help='Record data for targeted IP address only', required=False)
parser.add_argument('-s', '--sleep', help='Record data for targeted IP address only', required=False)
parser.add_argument('-j', '--jitter', help='Record data for targeted IP address only', required=False)

parser.add_argument('-a', '--append', help='If set, appends to existing csv', required=False, action='store_true')
parser.add_argument('-z', '--target', help='Record data for targeted IP address only', required=False)


parser.add_argument('-y', '--labelList', help='label ._____ as Good', required=False)
parser.add_argument('-x', '--ipLabel', help='ipOnly label', required=False, action='store_true')

args = vars(parser.parse_args())

start = time.time()

dirName = args['read']

label = args['label']
dataset = args['dataset']
owner = args['owner']
target = args['target']

outputCsvTcp = args['write']

timer = args['time']
string = ""
if args['time']:
    string += " -t " + args['time'] +" "

if args['target']:
    string += " -z " + args['target'] + " "

if args['append']:
    string += " -a "

if args['labelList']:
    string += " -y " + args['labelList'] + " "

if args['ipLabel']:
    string += " -x " + args['ipLabel'] + " "

if args['malware']:
    string += " -m " + args['malware'] + " "

if args['protocol']:
    string += " -p " + args['protocol'] + " "

if args['sleep']:
    string += " -s " + args['sleep'] + " "

if args['jitter']:
    string += " -j " + args['jitter'] + " "

count = 1

allFiles = glob.glob(dirName+ "/*/*.bz2")

for i in allFiles:
    cmd = 'bzip2 -dk '+i
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    print(p).stdout.readlines()
    newT = time.time()
    print(newT - start)
    fileName = i.rsplit('.', 1)[:-1][0]
    #dirPath = i.rsplit('/', 1)[:-1][0]
    #print(dirPath)
    cmd = 'tshark -r '+ fileName + ' -Y "(ip.addr== 10.1.70.20) and  (ip.addr!= 10.1.70.40 or ip.addr!= 10.1.70.41 or ip.addr!= 10.1.70.42 or ip.addr!= 10.1.70.43) and (! ldap or ! ftp or ! tpkt) and (dns or tcp)" -w temporary.pcap'
    print("****" + cmd)
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print(p).stdout.readlines()
    newT = time.time()
    print(newT - start)
    cmd = "python pcapToCsvs.py -r temporary.pcap -w tempTcp.csv -wd tempDNS.csv"
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print(p).stdout.readlines()
    print("****" + cmd)
    newT = time.time()
    print(newT - start)
    cmd = "python csvsToPandas.py -r tempTcp.csv -rd tempDNS.csv -w "+ outputCsvTcp + " -l "+ label + " -d " + dataset + " -o " + owner + string
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print("****" + cmd)
    #print(p).stdout.readlines()
    #newT = time.time()
    #print(newT - start)

    os.remove(fileName)


end = time.time()
print(end - start)