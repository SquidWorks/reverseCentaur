import argparse
import glob
import os
import time
from subprocess import Popen, PIPE, STDOUT


def readPcapToCSV(fileName, csvName):

    cmd = "tshark -E occurrence=f -nr " + fileName + " -Nn -T fields -e ip.src -e dns.resp.name -e dns.resp.addr -e dns.resp.len -e dns.resp.primaryname -e frame.time_epoch -Y 'dns.flags.response == 1 && dns.resp.name && dns.qry.type == 0x0001' >> " + csvName
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)


def cleanPcap(pcapFile):
    commandString = "pcapfix " + pcapFile
    p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.readlines()
    #print(output)

    try:
        commandString = "editcap -c 1000 " + "fixed_" + pcapFile + " " + pcapFile
        p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()
        #print(output)

    except:
        commandString = "editcap -c 1000 " + pcapFile + " " + "Split" +pcapFile
        p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()
        #print(output)

    time.sleep(2)
    fileCut = pcapFile.split(".")[0]
    preFixedFiles = sorted(glob.glob(fileCut+ "*.pcap*"))

    #print(preFixedFiles)
    return preFixedFiles

def cleanAndReadPcap(fileName):


    fixedFiles = cleanPcap(fileName)
    for files in fixedFiles:
        print(files)
        readPcapToCSV(files, csvName)
        if files != args['read']:
            os.remove(files)


start = time.time()

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Enter the filename of the packet capture to read', required=True)
parser.add_argument('-w','--write', help='Enter the filename of the csv to write', required=True)
parser.add_argument('-t','--type', help='Enter type of file: "file", "live", or "dir"', required=False, default='file')

args = vars(parser.parse_args())

fileName = args['read']
csvName = args['write']

if args['type'] == "live":
    readPcapToCSV(fileName, csvName)

elif args['type'] == "dir":
    allFiles = glob.glob(fileName+ "/*.pcap*")
    for pcapFile in allFiles:
        cleanAndReadPcap(pcapFile)

elif args['type'] == "file":
    cleanAndReadPcap(fileName)


else:
    print("Use -h to figure it out")


end = time.time()
print(end - start)