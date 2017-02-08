import csv
from collections import defaultdict
from subprocess import Popen, PIPE, STDOUT
import time
from operator import itemgetter
import pandas as pd
import re, os.path

def likelihoodsMake():


    word_file = "words.txt"
    log_filename = "filterlog.txt"
    likelihood_file = "likelihoods.txt"
    bigram_file = "bigrams.txt"

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

def bigramQuery(field):
    if len(field) > 1:
        for k in range(len(field)-1):

            this_ltr = field[k]

            next_ltr = field[k+1]
            this_idx = ord(this_ltr) - ord('a')

            next_idx = ord(next_ltr) - ord('a')


            field_likelihood = bigrams_float[this_idx][next_idx]*len(field)
        return field_likelihood
    else:
        return 0

def domainEnrich(domainName):
    domainNameFull = domainName
    subdomainName = domainNameFull.split(".")[:-2]

    subdomainNameJoined = (''.join(subdomainName)).lower()

    domainName = domainNameFull.split(".")[-2].lower()

    domainNameJoined = ('.'.join(domainNameFull.split(".")[-2:])).lower()

    subdomainDepth = len(subdomainName)
    subdomainLength = len(subdomainNameJoined)

    subdomainEntropy = len(subdomainNameJoined)/4

    subdomainNameJoined = subdomainNameJoined
    field = subdomainNameJoined.translate(None, '0123456789-')
    subdomainBigram = bigramQuery(field)

    domainEntropy = len(domainName)/4

    field = domainName.translate(None, '0123456789-')
    domainBigram = bigramQuery(field)
    return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram, subdomainName, domainNameJoined]

def enrichedArrayToDataFrame(SUPAHARRAY):

    df = pd.DataFrame(SUPAHARRAY)


    cols = [
            'domainName',
            'ipAddress',
            'label',
            'dataset',
            'owner',
            'count',
            'fqdns',
            'domainEntropy',
            'domainBigram',
            'subdomainEntropyAvg',
            'subdomainBigramAvg',
            'subdomainLengthAvg',
            'subdomainDepthAvg',
            'dataBytesAvg',
            'primaryFlag',
            'primaryCount',
            'domainPrimaryBigram',
            'domainPrimaryEntropy',
            'subdomainPrimaryBigramAvgTemp',
            'subdomainPrimaryEntropyAvgTemp',
            'subdomainPrimaryLengthAvgTemp',
            'subdomainPrimaryDepthAvgTemp'
        ]
    df.columns = cols

    df.to_csv('myDataFrame.csv', sep='\t')

    print(df)

def dictionaryEnricher(magicDictionary):
    SUPAHARRAY = []


    for i in magicDictionary:
        print(i)

        print(magicDictionary[i])
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
        domainPrimaryBigram = float(0)
        domainPrimaryEntropy = float(0)
        subdomainPrimaryBigramAvgTemp = float(0)
        subdomainPrimaryEntropyAvgTemp = float(0)
        subdomainPrimaryLengthAvgTemp = float(0)
        subdomainPrimaryDepthAvgTemp = float(0)
        primaryFlag = float(0)
        primaryCount = float(0)
        dataBytesAvgTemp = float(0)

        for j in magicDictionary[i]:


            domainName = j[2][7]

            domainBigram = j[2][5]
            domainEntropy = j[2][4]
            subdomainBigramAvgTemp += j[2][3]
            subdomainEntropyAvgTemp += j[2][2]
            subdomainLengthAvgTemp += j[2][1]
            subdomainDepthAvgTemp += j[2][0]
            dataBytesAvgTemp += float(j[4])

            if j[5] != "":
                domainPrimaryBigram = j[6][5]
                domainPrimaryEntropy = j[6][4]
                subdomainPrimaryBigramAvgTemp += j[6][3]
                subdomainPrimaryEntropyAvgTemp += j[6][2]
                subdomainPrimaryLengthAvgTemp += j[6][1]
                subdomainPrimaryDepthAvgTemp += j[6][0]
                primaryFlag = 1
                primaryCount += 1


            count += 1


        ipAddress = j[3]
        subdomainBigramAvg = float(subdomainBigramAvgTemp/count)
        subdomainEntropyAvg = float(subdomainEntropyAvgTemp/count)
        subdomainLengthAvg = float(subdomainLengthAvgTemp/count)
        subdomainDepthAvg = float(subdomainDepthAvgTemp/count)
        dataBytesAvg = float(dataBytesAvgTemp/count)

        if primaryFlag == 1:
            subdomainPrimaryBigramAvg = float(subdomainPrimaryBigramAvgTemp/primaryCount)
            subdomainPrimaryEntropyAvg = float(subdomainPrimaryEntropyAvgTemp/primaryCount)
            subdomainPrimaryLengthAvg = float(subdomainPrimaryLengthAvgTemp/primaryCount)
            subdomainDPrimaryepthAvg = float(subdomainPrimaryDepthAvgTemp/primaryCount)

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
        dataBytesAvg,
        primaryFlag,
        primaryCount,
        domainPrimaryBigram,
        domainPrimaryEntropy,
        subdomainPrimaryBigramAvgTemp,
        subdomainPrimaryEntropyAvgTemp,
        subdomainPrimaryLengthAvgTemp,
        subdomainPrimaryDepthAvgTemp

        ))

        SUPAHARRAY.append(tempArray)

    return SUPAHARRAY

def enrichToDictionary(csvName):
    with open(csvName, 'rb') as f:
        reader = csv.reader(f)
        bigArray = list(reader)

    magicDictionary = {}
    for i in bigArray:
        splitArray = i[0].split("\t")

        domainNameFull = splitArray[1]
        enriched = domainEnrich(domainNameFull)


        if splitArray[4] != "":
                primaryNameFull = splitArray[4]

                enrichedPrimary = domainEnrich(primaryNameFull)

                splitArray.insert(5, enrichedPrimary)

        splitArray.insert(2, enriched)

        dictKey = splitArray[0] + "x" + enriched[-1]
        if dictKey in magicDictionary:

            magicDictionary[dictKey].append(splitArray)


        else:


            magicDictionary[dictKey]= [splitArray]

    return magicDictionary


fileName = "test.pcapng"
csvName = "output.csv"
label = "Good"
dataset = "RIS"
owner = "Devey"


likelihoods = []
bigrams_float = []

likelihoodsMake()

magicDictionary = enrichToDictionary(csvName)

SUPAHARRAY = dictionaryEnricher(magicDictionary)

enrichedArrayToDataFrame(SUPAHARRAY)



