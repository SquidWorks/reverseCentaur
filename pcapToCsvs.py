import csv
from subprocess import Popen, PIPE, STDOUT
import time
import glob
import argparse
import os


""" This is a pre-processor for packet captures that takes in the data and parses it... think of it like a very shitty Bro. 
Why did I do it like this you might ask? I was feeling lazy and knew tshark would be super easy to get started with. #noregrets"""

def readPcapToDNSCSV(fileName, csvName):

    cmd = "tshark -E occurrence=f -nr " + fileName + " -Nn -T fields -e ip.src -e dns.resp.name -e dns.resp.addr -e dns.resp.len -e dns.resp.primaryname -e frame.time_epoch -Y 'dns.flags.response == 1 && dns.resp.name && dns.qry.type == 0x0001' >> " + csvName
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

def readPcapToCSV(fileName, csvName):


    print(fileName + " Started:")
    cmd = "tshark -r " + fileName + "-R 'tcp' -w " + fileName
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

    cmd = "tshark -r " + fileName + " -T fields -e frame.time_relative -e frame.time_epoch -Y 'frame.time_relative==0.000000000'"
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

    timeStart = p.stdout.read().strip().split("\t")[1]
    fixed= timeStart.split("\n")[0]
    #print("Time")


    bigArray = []
    commandString = "tshark -r " + fileName + " -q -z conv,tcp,"
    p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.readlines()
    for line in output:

        try:
            hello = line.split(" ")
            out = [x for x in hello if x]
            out3 = out[0].split(":") + out[2].split(":") + out[3:-2] + [float(out[-2])+float(fixed)]+ [out[-1].rstrip()]
            bigArray.append(out3)

        except:
            errorHandlingIsForScrubs = "I Ain't No Scrub"

    sortedArray = sorted(bigArray,key=lambda x: x[10])

    with open(csvName, "a") as f:
        writer = csv.writer(f)
        writer.writerows(sortedArray)

def cleanPcap(pcapFile):
    commandString = "pcapfix " + pcapFile
    p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.readlines()
    #print(output + "*")

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

def cleanAndReadPcap(fileName, csvName, DNScsvname):

    cmd = 'tshark -nr ' + fileName +' -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Nn -Y "tcp.dstport == 443" >> output.csv'
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTPS Done")


    cmd = 'tshark -nr ' + fileName +' -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Nn -Y "tcp" >> output2.csv'
    l = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTP Done")

    #fixedFiles = cleanPcap(fileName)
    #for files in fixedFiles:
    #    print(files)
    readPcapToCSV(fileName, csvName)
    readPcapToDNSCSV(fileName, DNScsvName)
    #    if files != args['read']:
    #        os.remove(files)




# start = time.time()
# I have time in for debugging purposes, gives me a good idea of how long shit can take

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
# Of all the argument parsers out there, I like argparse. Sue me.
parser.add_argument("-r", "--read", help='Enter the filename of the packet capture to read', required=True)

parser.add_argument('-w','--write', help='Enter the filename of the csv to write', required=True)

parser.add_argument('-wd','--writedns', help='Enter the filename of the DNS csv to write', required=True)

parser.add_argument('-t','--type', help='Enter type of file: "file", "live", or "dir"', required=False, default='file')
# file is....a  single file! live means it is a live capture and is actively growing (that is broken... whatevs)
# dir means you are loading a directory and it will take the name of the directory you want to load all at once
args = vars(parser.parse_args())

fileName = args['read']
csvName = args['write']
DNScsvName = args['writedns']


if args['type'] == "live":
    print("BROKEN")
    # I told you it was broken

elif args['type'] == "dir":
    allFiles = glob.glob(fileName+ "/*.pcap*")
    for pcapFile in allFiles:
        cleanAndReadPcap(pcapFile, csvName, DNScsvName)

elif args['type'] == "file":
    cleanAndReadPcap(fileName, csvName, DNScsvName)


else:
    print("Use -h to figure it out")


# end = time.time()
# timer stuff
# print(end - start)
