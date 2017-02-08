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

f = open('output.csv')
csv_f = csv.reader(f)

domain2ip = defaultdict(dict)

for row in csv_f:
    if len(row[0]) < 25:
        pass


    else:

        a = (row[0].split("\t"))
        #print(a)
        # This fails sometimes when the packet capture gets corrupted, we wind up having one and a half
        # Then the call for a[2] is
        b = a[2].split(".")
        if b[-1].isdigit() or b==[]:
            #then its an ip, skip it
            #perhaps should add ip detection
            #print(b[-1])
            pass
        else:
            domain2ip[a[1]] = [a[2]]

f = open('output2.csv')
csv_f = csv.reader(f)

for row in csv_f:
    if len(row[0]) < 25:
        pass


    else:

        a = (row[0].split("\t"))
        #print(a)
        b = a[2].split(".")
        if b[-1].isdigit() or b==[]:
            #then its an ip, skip it
            #perhaps should add ip detection
            #print(b[-1])
            pass
        else:
            domain2ip[a[1]] = [a[2]]


print("Dictionary Complete")


likelihoods = []
bigrams_float = []
# See if likelihood data exists. If not, generate
'''if not os.path.isfile(likelihood_file):

	print("No likelihood file...")

	# See if bigram data exists.
	if not os.path.isfile(bigram_file):		# If not, generate

		print("No bigram file, generating...")
		if not os.path.isfile(word_file):
			print("Need wordfile for bigrams, but not found")
		else:
			bigrams_float = compute_bigrams(word_file, bigram_file)
	else:									# If yes, import from file
		print("Reading bigram file...")
		bigrams = open(bigram_file,"r")
		for line in bigrams:
			bigram_row = []
			line_list = line.split()
			# print("line_list: " + str(line_list))
			for entry in line_list:
				bigram_row.append(float(entry))
			bigrams_float.append(bigram_row)
		bigrams.close()

	print("Computing likelihoods...")
	likelihoods = compute_likelihoods(word_file, bigrams_float)

else:
'''
if bigrams_float == []:
    bigrams = open(bigram_file,"r")
    for line in bigrams:
        bigram_row = []
        line_list = line.split()
        # print("line_list: " + str(line_list))
        for entry in line_list:
            bigram_row.append(float(entry))
        bigrams_float.append(bigram_row)
    bigrams.close()

like = open(likelihood_file, "r")
for line in like:
    likelihoods.append(float(line))
like.close()

print("Likelihoods Loaded")

with open(csvName, 'rb') as f:
    reader = csv.reader(f)
    bigArray = list(reader)


magicDictionary = {}
for i in bigArray:

    ipAddress = i[2]
    #print(i)
    #We need to create domain fields real quick
    newI = i

    if domain2ip[i[2]] != {}:
        if domain2ip[i[2]][0].split(".")[-1].isdigit():

            print("WE IN HERE")

            subdomainName = ''
            domainNameAndTld = 'digit'
            subdomainDepth = 0
            subdomainLength = 0
            subdomainEntropy = 0
            subdomainBigram = 0
            domainEntropy = 0
            domainBigram = 0

        else:
            domainNameFull = domain2ip[i[2]][0]


            subdomainName = domainNameFull.split(".")[:-2]


            subdomainNameJoined = (''.join(subdomainName)).lower()

            domainName = domainNameFull.split(".")[-2].lower()

            domainNameJoined = ('.'.join(domainNameFull.split(".")[-2:])).lower()

            subdomainDepth = len(subdomainName)
            subdomainLength = len(subdomainNameJoined)

            subdomainEntropy = len(subdomainNameJoined)/4

            subdomainNameJoined = subdomainNameJoined
            field = subdomainNameJoined.translate(None, '0123456789-')


            for k in range(len(field)-1):

                        this_ltr = field[k]

                        next_ltr = field[k+1]
                        this_idx = ord(this_ltr) - ord('a')

                        next_idx = ord(next_ltr) - ord('a')


                        field_likelihood = bigrams_float[this_idx][next_idx]*len(field)


            subdomainBigram = field_likelihood

            domainEntropy = len(domainName)/4


            field = domainName.translate(None, '0123456789-')


            for j in range(len(field)-1):

                        this_ltr = field[j]
                        next_ltr = field[j+1]
                        this_idx = ord(this_ltr) - ord('a')

                        next_idx = ord(next_ltr) - ord('a')


                        field_likelihood = bigrams_float[this_idx][next_idx]*len(field)

            domainBigram = field_likelihood

    else:
        subdomainName = ''

        domainNameJoined = 'none'
        subdomainDepth = 0
        subdomainLength = 0
        subdomainEntropy = 0
        subdomainBigram = 0
        domainEntropy = 0
        domainBigram = 0




    bytesPerFrameFrom = float(i[5])/float(i[4])
    bytesPerFrameTo = float(i[7])/float(i[6])

    #"ip.local srcport ip.dst dstport domainName subdomainName domainEntropy subdomainEntropy subdomainLength subdomainDepth framesFrom bytesFrom bytesPerFrameFrom framesTo bytesTo bytesPerFrameTo framesTotal bytesTotal timeStartFromEpoch timeDuration"

    newI.insert(4, subdomainDepth)
    newI.insert(4, subdomainLength)
    newI.insert(4, subdomainEntropy)
    newI.insert(4, subdomainBigram)
    newI.insert(4, domainEntropy)
    newI.insert(4, domainBigram)
    newI.insert(4, subdomainName)
    newI.insert(4, domainNameJoined)
    newI.insert(14, bytesPerFrameFrom)
    newI.insert(16, bytesPerFrameTo)

    dictKey = i[0] + "x" + domainNameJoined
    if dictKey in magicDictionary:



        #print(magicDictionary[dictKey])
        #print("AAA")
        #print(i)
        magicDictionary[dictKey].append(newI)




    else:


        magicDictionary[dictKey]= [newI]

print("Domain Dictionary Made")

SUPAHARRAY = []

################################################################################################


for i in magicDictionary:
    #print(i)
    #print(magicDictionary[i])
    tempArray = []
    label = "Good"
    count = 0
    fqdns = 0
    subDomainArray = []
    domainEntropy = float(0)
    domainBigram = float(0)
    subdomainEntropyAvg = float(0)
    subdomainEntropyAvgTemp = float(0)
    subdomainBigramAvg = float(0)
    subdomainBigramAvgTemp = float(0)
    subdomainLengthAvg = float(0)
    subdomainLengthAvgTemp = float(0)
    subdomainDepthAvg = float(0)
    subdomainDepthAvgTemp = float(0)
    framesFromAvg = float(0)
    framesFromTotal = 0
    bytesFromAvg = float(0)
    bytesFromTotal = 0
    bytesPerFrameFromTemp = float(0)
    framesToAvg = float(0)
    framesToTotal = 0
    bytesToAvg = float(0)
    bytesToTotal = 0
    bytesPerFrameToTemp = float(0)
    framesTotalTotal = 0
    bytesTotalTotal = 0
    for j in magicDictionary[i]:


        domainName = j[4]



        if j[5] not in subDomainArray:
            fqdns += 1

        domainBigram = j[6]

        domainEntropy = j[7]
        subdomainBigramAvgTemp += j[8]
        subdomainEntropyAvgTemp += j[9]
        subdomainLengthAvgTemp += j[10]
        subdomainDepthAvgTemp += j[11]


        framesFromTotal += float(j[12])
        bytesFromTotal += float(j[13])
        bytesPerFrameFromTemp += float(j[14])
        framesToTotal += float(j[15])
        bytesToTotal += float(j[16])
        bytesPerFrameToTemp = float(j[17])
        framesTotalTotal += float(j[18])
        bytesTotalTotal += float(j[19])
        count += 1


    ipAddress = j[2]
    subdomainBigramAvg = float(subdomainBigramAvgTemp/count)

    subdomainEntropyAvg = float(subdomainEntropyAvgTemp/count)
    subdomainLengthAvg = float(subdomainLengthAvgTemp/count)
    subdomainDepthAvg = float(subdomainDepthAvgTemp/count)

    framesFromAvg = float(framesFromTotal/count)
    bytesFromAvg = float(bytesFromTotal/count)
    bytesPerFrameFromAvg = float(bytesPerFrameFromTemp/count)
    framesToAvg = float(framesToTotal/count)
    bytesToAvg = float(bytesToTotal/count)
    bytesPerFrameToAvg = float(bytesPerFrameToTemp/count)



    tempArray.extend((
    domainName,
    ipAddress,
    label,
    dataset,
    owner,
    count,
    fqdns,
    domainEntropy,
    domainBigram,
    subdomainEntropyAvg,
    subdomainBigramAvg,
    subdomainLengthAvg,
    subdomainDepthAvg,
    framesFromAvg,
    framesFromTotal,
    bytesFromAvg,
    bytesFromTotal,
    bytesPerFrameFromTemp,
    framesToAvg,
    framesToTotal,
    bytesToAvg,
    bytesToTotal,
    bytesPerFrameToAvg,
    framesTotalTotal,
    bytesTotalTotal
    ))

    SUPAHARRAY.append(tempArray)


#print(sorted(SUPAHARRAY, key=itemgetter(-1)))


df = pd.DataFrame(SUPAHARRAY)
cols = ['domainName', 'ipAddress', 'label', 'dataset', 'owner', 'count', 'fqdns', 'domainEntropy', 'domainBigram', 'subdomainEntropyAvg', 'subdomainBigramAvg', 'subdomainLengthAvg', 'subdomainDepthAvg', 'framesFromAvg', 'framesFromTotal', 'bytesFromAvg', 'bytesFromTotal', 'bytesPerFrameFrom', 'framesToAvg', 'framesToTotal', 'bytesToAvg', 'bytesToTotal', 'bytesPerFrameToAvg', 'framesTotalTotal', 'bytesTotalTotal']

df.columns = cols

df.to_csv('myDataFrame.csv', sep='\t')

print(df)




