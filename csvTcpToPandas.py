import csv
from collections import defaultdict
import pandas as pd
import argparse
from collections import Counter
import math
import time
from scipy import stats

def dictionaryMaker(csvOne, csvTwo):
    f = open(csvOne)
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

    f = open(csvTwo)
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

    return domain2ip

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


            field_likelihood = bigrams_float[this_idx][next_idx]*2*len(field)
        return field_likelihood
    else:
        return 0

def entropy(s):
    p, lns =Counter(s), float(len(s))
    return (-sum(count/lns * math.log(count/lns,2) for count in p.values()))

def domainEnrich(domainNameFull):
    subdomainName = domainNameFull.split(".")[:-2]


    subdomainNameJoined = (''.join(subdomainName)).lower()

    domainName = domainNameFull.split(".")[-2].lower()

    domainNameJoined = ('.'.join(domainNameFull.split(".")[-2:])).lower()

    subdomainDepth = len(subdomainName)
    subdomainLength = len(subdomainNameJoined)

    subdomainEntropy = entropy(subdomainNameJoined)

    subdomainNameJoined = subdomainNameJoined

    field = subdomainNameJoined.translate(None, '0123456789-') # PROBLEM CHILD
    subdomainBigram = bigramQuery(field)

    domainEntropy = entropy(domainName)

    field = domainName.translate(None, '0123456789-') # PROBLEM CHILD
    domainBigram =  bigramQuery(field)
    return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram, subdomainName, domainNameJoined]

def enrichToDictionary(csvName):
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

                enriched = domainEnrich(domainNameFull)
                #return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram, subdomainName, domainNameJoined]
                subdomainDepth = enriched[0]
                subdomainLength = enriched[1]
                subdomainEntropy = enriched[2]
                subdomainBigram = enriched[3]
                domainEntropy = enriched[4]
                domainBigram = enriched[5]
                subdomainName = enriched[6]
                domainNameJoined = enriched[7]


        else:
            subdomainName = ''

            domainNameJoined = 'none'
            subdomainDepth = 0
            subdomainLength = 0
            subdomainEntropy = 0
            subdomainBigram = 0
            domainEntropy = 0
            domainBigram = 0




        try: bytesPerFrameFrom = float(i[5])/float(i[4])
        except:
            bytesPerFrameFrom = 0

        try: bytesPerFrameTo = float(i[7])/float(i[6])
        except:
            bytesPerFrameTo = 0

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

    return magicDictionary

def dictionaryEnricher(magicDictionary):
    SUPAHARRAY = []



    for i in magicDictionary:

        #print(i)
        #print(magicDictionary[i])
        tempArray = []
        statisticsArray = []

        fqdns = 0
        count = 0
        subDomainArray = []
        subdomainBigramAvgList = []
        subdomainEntropyAvgList = []
        subdomainLengthAvgList = []
        subdomainDepthAvgList = []
        framesFromList = []
        bytesFromList = []
        bytesPerFrameFromList = []
        framesToList = []
        bytesToList = []
        bytesPerFrameToList = []

        # [0] = subdomainBigram,
        # [1] = subdomainEntropy,
        # [2] = subdomainLength,
        # [3] = subdomainDepth,
        # [4]= framesFrom,
        # [5] = bytesFrom,
        # [6] = bytesPerFrame,
        # [7] = framesTo,
        # [8] = bytesTo,
        # [9] = bytesPerFrame


        framesFromTotal = 0
        bytesFromTotal = 0
        framesToTotal = 0
        bytesToTotal = 0
        framesTotalTotal = 0
        bytesTotalTotal = 0

        for j in magicDictionary[i]:
            count += 1
            domainName = j[4]



            if j[5] not in subDomainArray:
                fqdns += 1

            domainBigram = j[6]
            domainEntropy = j[7]



            subdomainBigramAvgList.append(j[8])
            subdomainEntropyAvgList.append(j[9])
            subdomainLengthAvgList.append(j[10])
            subdomainDepthAvgList.append(j[11])
            framesFromList.append(float(j[12]))
            framesFromTotal += float(j[12])
            bytesFromList.append(float(j[13]))
            bytesFromTotal += float(j[13])
            bytesPerFrameFromList.append(float(j[14]))
            framesToList.append(float(j[15]))
            framesToTotal += float(j[15])
            bytesToList.append(float(j[16]))
            bytesToTotal += float(j[16])
            bytesPerFrameToList.append(float(j[17]))
            framesTotalTotal += float(j[18])
            bytesTotalTotal += float(j[19])

        ipAddress = j[2]

        listOfArrays= [ subdomainBigramAvgList,
                        subdomainEntropyAvgList,
                        subdomainLengthAvgList,
                        subdomainDepthAvgList,
                        framesFromList,
                        bytesFromList,
                        bytesPerFrameFromList,
                        framesToList,
                        bytesToList,
                        bytesPerFrameToList]




        # [0] = subdomainBigram,
        # [1] = subdomainEntropy,
        # [2] = subdomainLength,
        # [3] = subdomainDepth,
        # [4]= framesFrom,
        # [5] = bytesFrom,
        # [6] = bytesPerFrame,
        # [7] = framesTo,
        # [8] = bytesTo,
        # [9] = bytesPerFrame
        for i in listOfArrays:
            listOfListOfFeatures = [[]]*9
            listOfListOfFeatures[0] = float(sum(i)/(len(i))) #Average
            listOfListOfFeatures[1] = min(i) #min
            listOfListOfFeatures[2] = max(i) #max
            listOfListOfFeatures[3] = stats.mode(i)[0][0] #mode
            listOfListOfFeatures[4] = stats.mode(i)[1][0] #mode count
            if listOfListOfFeatures[4] == 1: #if modecount = 1
                listOfListOfFeatures[4] = 0 # set = 0
            listOfListOfFeatures[5] = stats.entropy(i)  #entropy
            if math.isnan(listOfListOfFeatures[5]): #if is not a number
                listOfListOfFeatures[4] = 0 # set = 0
                listOfListOfFeatures[5] = 0 # set = 0
            listOfListOfFeatures[6] = stats.variation(i) #variation
            if math.isnan(listOfListOfFeatures[6]): #if is not a number
                listOfListOfFeatures[6] = 0 # set = 0
            listOfListOfFeatures[7] = stats.skew(i) #skew
            listOfListOfFeatures[8] = stats.kurtosis(i) #kurtosis

            statisticsArray.append(listOfListOfFeatures)



        flatList = [item for sublist in statisticsArray for item in sublist]

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
        ))

        tempArray.extend(flatList)

        tempArray.extend((
        framesFromTotal,
        bytesFromTotal,
        framesToTotal,
        bytesToTotal,
        framesTotalTotal,
        bytesTotalTotal
        ))

        SUPAHARRAY.append(tempArray)

    return SUPAHARRAY

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
            'subdomainBigramAvg',
            'subdomainBigramMin',
            'subdomainBigramMax',
            'subdomainBigramMode',
            'subdomainBigramModeCount',
            'subdomainBigramEntropy',
            'subdomainBigramVariation',
            'subdomainBigramSkew',
            'subdomainBigramKurtosis',
            'subdomainEntropyAvg',
            'subdomainEntropyMin',
            'subdomainEntropyMax',
            'subdomainEntropyMode',
            'subdomainEntropyModeCount',
            'subdomainEntropyEntropy',
            'subdomainEntropyVariation',
            'subdomainEntropySkew',
            'subdomainEntropyKurtosis',
            'subdomainLengthAvg',
            'subdomainLengthMin',
            'subdomainLengthMax',
            'subdomainLengthMode',
            'subdomainLengthModeCount',
            'subdomainLengthEntropy',
            'subdomainLengthVariation',
            'subdomainLengthSkew',
            'subdomainLengthKurtosis',
            'subdomainDepthAvg',
            'subdomainDepthMin',
            'subdomainDepthMax',
            'subdomainDepthMode',
            'subdomainDepthModeCount',
            'subdomainDepthEntropy',
            'subdomainDepthVariation',
            'subdomainDepthSkew',
            'subdomainDepthKurtosis',
            'framesFromAvg',
            'framesFromMin',
            'framesFromMax',
            'framesFromMode',
            'framesFromModeCount',
            'framesFromEntropy',
            'framesFromVariation',
            'framesFromSkew',
            'framesFromKurtosis',
            'bytesFromAvg',
            'bytesFromAMin',
            'bytesFromAMax',
            'bytesFromAMode',
            'bytesFromAModeCount',
            'bytesFromAEntropy',
            'bytesFromAVariation',
            'bytesFromASkew',
            'bytesFromAKurtosis',
            'bytesPerFrameFromAvg',
            'bytesPerFrameFromMin',
            'bytesPerFrameFromMax',
            'bytesPerFrameFromMode',
            'bytesPerFrameFromModeCount',
            'bytesPerFrameFromEntropy',
            'bytesPerFrameFromVariation',
            'bytesPerFrameFromSkew',
            'bytesPerFrameFromKurtosis',
            'framesToAvg',
            'framesToMin',
            'framesToMax',
            'framesToMode',
            'framesToModeCount',
            'framesToEntropy',
            'framesToVariation',
            'framesToSkew',
            'framesToKurtosis',
            'bytesToAvg',
            'bytesToMin',
            'bytesToMax',
            'bytesToMode',
            'bytesToModeCount',
            'bytesToEntropy',
            'bytesToVariation',
            'bytesToSkew',
            'bytesToKurtosis',
            'bytesPerFrameToAvg',
            'bytesPerFrameToMin',
            'bytesPerFrameToMax',
            'bytesPerFrameToMode',
            'bytesPerFrameToModeCount',
            'bytesPerFrameToEntropy',
            'bytesPerFrameToVariation',
            'bytesPerFrameToSkew',
            'bytesPerFrameToKurtosis',
            'framesFromTotal',
            'bytesFromTotal',
            'framesToTotal',
            'bytesToTotal',
            'framesTotalTotal',
            'bytesTotalTotal'
        ]

    df.columns = cols

    df.to_csv(outputFile, mode='a', header=True, sep='\t')

    print(df)

def enrichedArrayToDataFrameTime(SUPAHARRAY, labelFlag):
    print("EnAR2DaFr")
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
            'subdomainBigramAvg',
            'subdomainBigramMin',
            'subdomainBigramMax',
            'subdomainBigramMode',
            'subdomainBigramModeCount',
            'subdomainBigramEntropy',
            'subdomainBigramVariation',
            'subdomainBigramSkew',
            'subdomainBigramKurtosis',
            'subdomainEntropyAvg',
            'subdomainEntropyMin',
            'subdomainEntropyMax',
            'subdomainEntropyMode',
            'subdomainEntropyModeCount',
            'subdomainEntropyEntropy',
            'subdomainEntropyVariation',
            'subdomainEntropySkew',
            'subdomainEntropyKurtosis',
            'subdomainLengthAvg',
            'subdomainLengthMin',
            'subdomainLengthMax',
            'subdomainLengthMode',
            'subdomainLengthModeCount',
            'subdomainLengthEntropy',
            'subdomainLengthVariation',
            'subdomainLengthSkew',
            'subdomainLengthKurtosis',
            'subdomainDepthAvg',
            'subdomainDepthMin',
            'subdomainDepthMax',
            'subdomainDepthMode',
            'subdomainDepthModeCount',
            'subdomainDepthEntropy',
            'subdomainDepthVariation',
            'subdomainDepthSkew',
            'subdomainDepthKurtosis',
            'framesFromAvg',
            'framesFromMin',
            'framesFromMax',
            'framesFromMode',
            'framesFromModeCount',
            'framesFromEntropy',
            'framesFromVariation',
            'framesFromSkew',
            'framesFromKurtosis',
            'bytesFromAvg',
            'bytesFromAMin',
            'bytesFromAMax',
            'bytesFromAMode',
            'bytesFromAModeCount',
            'bytesFromAEntropy',
            'bytesFromAVariation',
            'bytesFromASkew',
            'bytesFromAKurtosis',
            'bytesPerFrameFromAvg',
            'bytesPerFrameFromMin',
            'bytesPerFrameFromMax',
            'bytesPerFrameFromMode',
            'bytesPerFrameFromModeCount',
            'bytesPerFrameFromEntropy',
            'bytesPerFrameFromVariation',
            'bytesPerFrameFromSkew',
            'bytesPerFrameFromKurtosis',
            'framesToAvg',
            'framesToMin',
            'framesToMax',
            'framesToMode',
            'framesToModeCount',
            'framesToEntropy',
            'framesToVariation',
            'framesToSkew',
            'framesToKurtosis',
            'bytesToAvg',
            'bytesToMin',
            'bytesToMax',
            'bytesToMode',
            'bytesToModeCount',
            'bytesToEntropy',
            'bytesToVariation',
            'bytesToSkew',
            'bytesToKurtosis',
            'bytesPerFrameToAvg',
            'bytesPerFrameToMin',
            'bytesPerFrameToMax',
            'bytesPerFrameToMode',
            'bytesPerFrameToModeCount',
            'bytesPerFrameToEntropy',
            'bytesPerFrameToVariation',
            'bytesPerFrameToSkew',
            'bytesPerFrameToKurtosis',
            'framesFromTotal',
            'bytesFromTotal',
            'framesToTotal',
            'bytesToTotal',
            'framesTotalTotal',
            'bytesTotalTotal'
        ]

    df.columns = cols
    if labelFlag == 1:
        df.to_csv(outputFile, mode='a', header=True, sep='\t')
    else:
        df.to_csv(outputFile, mode='a', header=False, sep='\t')

    print(df)

start = time.time()

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Description for readFile argument', required=True)
parser.add_argument('-w','--write', help='Description for write argument', required=True)
parser.add_argument('-t','--time', help='Description for time argument', required=False, default='std')
parser.add_argument('-l','--label', help='Description for write argument', required=True)
parser.add_argument('-d','--dataset', help='Description for write argument', required=True)
parser.add_argument('-o','--owner', help='Description for write argument', required=True)

args = vars(parser.parse_args())


csvName = args['read']
csvOne = 'output.csv'
csvTwo = 'output2.csv'


label = args['label']
dataset = args['dataset']
owner = args['owner']

outputFile = args['write']

timer = args['time']

likelihoods = []
bigrams_float = []

likelihoodsMake()

domain2ip = dictionaryMaker(csvOne, csvTwo)

if timer == 'std':

    magicDictionary = enrichToDictionary(csvName)

    SUPAHARRAY = dictionaryEnricher(magicDictionary)

    enrichedArrayToDataFrame(SUPAHARRAY)

else:
    with open(csvName, 'rb') as f:
        reader = csv.reader(f)
        bigArray = list(reader)

    startTime = float(bigArray[0][10])
    print("STARTING")
    print(startTime)
    timeArray = []
    labelFlag = 1
    for i in bigArray:
        #print(i)
        if startTime + float(timer) > float(i[10]):
            timeArray.append(i)

        else:
            with open("tmp.csv", "w") as f:
                    writer = csv.writer(f)
                    writer.writerows(timeArray)
            magicDictionary = enrichToDictionary("tmp.csv")

            SUPAHARRAY = dictionaryEnricher(magicDictionary)

            enrichedArrayToDataFrameTime(SUPAHARRAY, labelFlag)
            #print(timeArray)
            timeArray = []

            labelFlag = 0
            startTime = startTime + 10

end = time.time()
print(end - start)
