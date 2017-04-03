import csv
from subprocess import Popen, PIPE, STDOUT
import time
import glob
import argparse
import os


def readPcapToCSV(fileName, csvName, defaultDeadCounter):


    print(fileName + " Started:")
    cmd = "tshark -r " + fileName + "-R 'tcp' -w " + fileName
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

    cmd = "tshark -nr " + fileName + " -T fields -e frame.time_relative -e frame.time_epoch -Y 'frame.time_relative==0.000000000'"
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

    timeStart = p.stdout.read().strip().split("\t")[1]
    fixed= timeStart.split("\n")[0]
    #print("Time")


    counter = 0
    deadCounter = defaultDeadCounter
    bigArray = []
    flag = 0
    commandString = "tshark -nr " + fileName + " -Nn -q -z conv,tcp,'tcp.stream eq " + str(counter) + "'"
    pTest = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    outputTest = pTest.stdout.readlines()[5]
    helloTest = outputTest.split(" ")
    outTest = [x for x in helloTest if x]

    try:
        out3Test = outTest[0].split(":") + outTest[2].split(":") + outTest[3:-2] + [float(outTest[-2])+float(fixed)]+ [outTest[-1].rstrip()]
        readlinesNum = 5
    except:
        readlinesNum = 6

    while flag == 0:
        try:
            commandString = "tshark -nr " + fileName + " -Nn -q -z conv,tcp,'tcp.stream eq " + str(counter) + "'"
            p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
            output = p.stdout.readlines()[readlinesNum]
            hello = output.split(" ")
            out = [x for x in hello if x]
            out3 = out[0].split(":") + out[2].split(":") + out[3:-2] + [float(out[-2])+float(fixed)]+ [out[-1].rstrip()]


            bigArray.append(out3)
            counter += 1
            #print(counter)
            deadCounter = defaultDeadCounter

        except IndexError:
            if deadCounter < 5:
                deadCounter += 1
                print(deadCounter)
                time.sleep(5)
            else:
                with open(csvName, "a") as f:
                    writer = csv.writer(f)
                    writer.writerows(bigArray)
                flag = 1

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

    cmd = 'tshark -r ' + fileName +' -Nn -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp.dstport == 443" >> output.csv'
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTPS Done")


    cmd = 'tshark -r ' + fileName +' -Nn -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp" >> output2.csv'
    l = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTP Done")

    fixedFiles = cleanPcap(fileName)
    for files in fixedFiles:
        print(files)
        readPcapToCSV(files, csvName, 5)
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
    readPcapToCSV(fileName, csvName, 0)

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