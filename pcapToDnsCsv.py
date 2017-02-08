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
csvName = "output.csv"
label = "Good"
dataset = "Random Internet Surfing"
owner = "Devey"


cmd = "tshark -E occurrence=f -nr test.pcapng -Nn -T fields -e ip.src -e dns.resp.name -e dns.resp.addr -e dns.resp.len -e dns.resp.primaryname -e frame.time_epoch -Y 'dns.flags.response == 1 && dns.resp.name && dns.qry.type == 0x0001' > output.csv"


p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

print("Done")



'''with open(csvName, "a") as f:
    writer = csv.writer(f)
    writer.writerows(bigArray)

print("CSV Created")'''
