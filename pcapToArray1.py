import csv
from collections import defaultdict
from subprocess import Popen, PIPE, STDOUT
import time
from operator import itemgetter
import pandas as pd
import re, os.path



word_file = "words.txt"
log_filename = "filterlog.txt"
likelihood_file = "likelihoods.txt"
bigram_file = "bigrams.txt"



fileName = "test.pcapng"
csvName = "arrayOne.csv"
label = "Good"
dataset = "Random Internet Surfing"
owner = "Devey"


cmd = "tshark -nr " + fileName + " -T fields -e frame.time_relative -e frame.time_epoch -Y 'frame.time_relative==0.000000000'"

p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
timeStart = p.stdout.read().strip().split("\t")[1]
print("Time")

cmdNumber = "tshark -r " + fileName +" -T fields -e tcp.stream | sort | uniq | wc -l"
p = Popen(cmdNumber, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
totalStreams = int(p.stdout.read().strip())-1
print("# of Streams")


cmd = 'tshark -r ' + fileName +' -Nn -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp.dstport == 443" > output.csv'

p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

time.sleep(2)


cmd = 'tshark -r ' + fileName +' -Nn -T fields -e frame.time_epoch -e ip.dst -e ip.dst_host -Y "tcp" > output2.csv'

p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

time.sleep(2)

stringOfFields = "ip.local srcport ip.dst dstport domainName subdomainName domainEntropy subdomainEntropy subdomainLength subdomainDepth framesFrom bytesFrom framesTo bytesTo framesTotal bytesTotal timeStartFromEpoch timeDuration"

stringOfFieldsDomain = "ip.local srcport ip.dst dstport filler #FQDNs domainEntropyAvg subdomainEntropyAvg subdomainLengthAvg subdomainDepthAvg framesFromAvg framesFromTotal bytesFromAvg bytesFromTotal framesToAvg framesToTotal bytesToAvg bytesToTotal framesTotalTotal bytesTotalTotal degreeOfPeriodicity degreeOfPseudorandomness timeStartFromEpoch timeDuration"
#print(stringOfFields)

counter = 0
bigArray = []

while counter < totalStreams:
    commandString = "tshark -nr " + fileName + " -Nn -q -z conv,tcp,'tcp.stream eq " + str(counter) + "'"
    p = Popen(commandString, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.readlines()[5]
    hello = output.split(" ")
    out = [x for x in hello if x]

    out3 = out[0].split(":") + out[2].split(":") + out[3:-2] + [float(out[-2])+float(timeStart)]+ [out[-1].rstrip()]


    #print(out3)
    bigArray.append(out3)
    counter += 1

with open(csvName, "wb") as f:
    writer = csv.writer(f)
    writer.writerows(bigArray)

print("CSV Created")
