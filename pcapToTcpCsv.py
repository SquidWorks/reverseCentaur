import csv
from subprocess import Popen, PIPE, STDOUT
import time
import glob
import argparse
from Queue import Queue
import threading


def getTcpStreamConvo(counter):
    commandString = "tshark -nr " + fileName + " -q -z conv,tcp,'tcp.stream == " + str(counter) + "'" #tshark-ing the conversation data for each indiviual tcp.stream sequentially.
    p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    try:
        output = p.stdout.readlines()[5]
    except:
        output = p.stdout.readlines()[6]

    hello = output.split(" ")
    out = [x for x in hello if x]
    out3 = out[0].split(":") + out[2].split(":") + out[3:-2] + [float(out[-2])+float(fixed)]+ [out[-1].rstrip()]
    #print(counter)
    with lock:
        array.append(out3)
        #print("Done: " + str(counter))

def worker():
    while True:
        item = q.get()
        getTcpStreamConvo(item)
        q.task_done()

def readPcapToCSV(fileName, csvName, defaultDeadCounter):


    print(fileName + " Started:")
    #cmd = "tshark -r " + fileName + "-R 'tcp' -w " + fileName
    #p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)



    #########
    # It's ugly, but it works pretty well.
    # Remember, ignore it, just pass correct readLinesNum value
    #########
    time.sleep(2)
    cmd = "tshark -r " + fileName + " -T fields -e tcp.stream | sort -rn | awk '!x[$2]++'"
    pTest = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    counterMax = int(pTest.stdout.readlines()[0].rstrip())
    #print(counterMax)

    """ *******************************************
    ***********************************************
    Parralelize This While Loop:
    The tshark counter command should be fairly simple to do.
    I don't know how to pass a flag all the way back to end the while loop though.
    ************************************************
    ************************************************"""

    for i in range(num_threads):
            print(str(i) + " thread number")
            t = threading.Thread(target = worker)
            t.setDaemon(True)
            t.start()

    for j in range(counterMax):
        q.put(j)

    q.join()


            #once all threads have finished
    #bigArray.append(output)
    #counter += 1
    #print(counter)
    #with open(csvName, "a") as f:
    #    writer = csv.writer(f)
    #    writer.writerows(bigArray)




    """ *******************************************
    ***********************************************
    Parralelize This While Loop:
    The tshark counter command should be fairly simple to do.
    I don't know how to pass a flag all the way back to end the while loop though.
    ************************************************
    ************************************************"""


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

    cmd = 'tshark -r ' + fileName +' -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp.dstport == 443" >> output.csv'
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTPS Done")


    cmd = 'tshark -r ' + fileName +' -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp" >> output2.csv'
    l = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #print("HTTP Done")

    #fixedFiles = cleanPcap(fileName)
    #for files in fixedFiles:
    #    print(files)
    readPcapToCSV(fileName, csvName, 5)
    #    if files != args['read']:
    #        os.remove(files)




start = time.time()

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Enter the filename of the packet capture to read', required=True)
parser.add_argument('-w','--write', help='Enter the filename of the csv to write', required=True)
parser.add_argument('-t','--type', help='Enter type of file: "file", "live", or "dir"', required=False, default='file')

args = vars(parser.parse_args())

fileName = args['read']
csvName = args['write']

lock = threading.Lock()
array = []
q = Queue()
num_threads= 6

cmd = "tshark -r " + fileName + " -T fields -e frame.time_relative -e frame.time_epoch -Y 'frame.time_relative==0.000000000'"
p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

timeStart = p.stdout.read().strip().split("\t")[1]
fixed= timeStart.split("\n")[0]
#print("Time")
print("Time completed")

########
# This next section doesn't make much sense. Depending on how the pcap is generated, there can be a different amount of space
# before the actual data we want to parse starts. This section parses it out for us, tests, and sets readLinesNum properly.
# You just have to pass the correct readLinesNum parameter into the function which will eventually be multi-threaded
########
commandString = "tshark -nr " + fileName + " -q -z conv,tcp,'tcp.stream eq 0'"
#print(commandString)
pTest = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
outputTest = pTest.stdout.readlines()[5]
helloTest = outputTest.split(" ")
outTest = [x for x in helloTest if x]

try:
    out3Test = outTest[0].split(":") + outTest[2].split(":") + outTest[3:-2] + [float(outTest[-2])+float(fixed)]+ [outTest[-1].rstrip()]
    readlinesNum = 5

except:
    readlinesNum = 6


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

test_file = open(csvName,'w') #open file
csvwriter = csv.writer(test_file) #set csv writing settings
for row in array: #write to csv file
    csvwriter.writerow(row)
test_file.close()


#print(array)

end = time.time()
print(end - start)