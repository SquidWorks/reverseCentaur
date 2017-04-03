import os
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
parser.add_argument('-a', '--append', help='If set, appends to existing csv', required=False, action='store_true')
parser.add_argument('-z', '--target', help='Record data for targeted IP address only', required=False)

args = vars(parser.parse_args())

start = time.time()

dirName = args['read']

label = args['label']
dataset = args['dataset']
owner = args['owner']
target = args['target']

outputCsv = args['write']

timer = args['time']
string = ""
if args['time']:
    string += " -t " + args['time'] +" "
if args['target']:
    string += " -z " + args['target'] + " "



count = 1

allFiles = glob.glob(dirName+ "/*.pcap*")

for i in allFiles:
    print('unBzip '+i)
    fileName = i.rsplit('.', 1)[:-1][0]
    print('tshark -r' + fileName + "-R ip.addr==1.1.1.1 or ip.addr==1.1.1.1 or ip.addr==1.1.1.1 or ip.addr==1.1.1.1 -w temporary.pcap")

    print("python pcapToTcpCsv.py -r temporary.pcap -w tempTcp.csv")
    print("python csvTcpToPandas.py -r tempTcp.csv -w " + outputCsv + " -l "+ label + " -d " + dataset + " -o " + owner + string)
    print("python pcapToDnsCsv.py -r -r temporary.pcap -w tempDns.csv")
    print("python csvDnsToPandas.py -r tempDns.csv -w " + outputCsv + " -l "+ label + " -d " + dataset + " -o " + owner + string)
    print("python remove temporary.pcap")
    print("python remove tempTcp.csv")
    print("python remove tempDns.csv")

end = time.time()
print(end - start)