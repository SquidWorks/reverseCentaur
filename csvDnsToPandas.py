import csv
from collections import defaultdict
import pandas as pd
import argparse
from collections import Counter
import math
import time
import glob
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
    return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram, domainNameJoined]

def enrichToDictionary(csvName):

    with open(csvName, 'rb') as f:
        reader = csv.reader(f)
        bigArray = list(reader)
    magicDictionary = {}
    for i in bigArray:
        splitArray = i[0].split("\t")

        dnsRespNameFull = splitArray[1]
        enriched = domainEnrich(dnsRespNameFull)


        if splitArray[4] != "":
                dnsRespPrimaryNameFull = splitArray[4]

                enrichedPrimary = domainEnrich(dnsRespPrimaryNameFull)

                splitArray.insert(5, enrichedPrimary)
        else:
            splitArray.insert(5, [0]*7) # if there is no primaryResponseName, make everything zeros
        splitArray.insert(2, enriched)

        dictKey = splitArray[0] + "x" + enriched[-1]
        if dictKey in magicDictionary:

            magicDictionary[dictKey].append(splitArray)


        else:


            magicDictionary[dictKey]= [splitArray]

    return magicDictionary

def dictionaryEnricher(magicDictionary):
    SUPAHARRAY = []

    for i in magicDictionary:

        #print(i)
        #print(magicDictionary[i])
        tempArray = []
        statisticsArray = []

        fqdns = 0
        primaryfqdns = 0
        ips = 0
        count = 0

        subDomainArray = []
        primarySubDomainArray = []
        ipArray = []

        subdomainBigramAvgList = []
        subdomainEntropyAvgList = []
        subdomainLengthAvgList = []
        subdomainDepthAvgList = []

        primarySubdomainDepthAvgList= []
        primarySubdomainLengthAvgList= []
        primarySubdomainEntropyAvgList= []
        primarySubdomainBigramAvgList= []
        primaryDomainEntropy = []
        primaryDomainBigram = []


        dataLengthList = []


        timeList = []

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


        dataLengthTotal = 0

        for j in magicDictionary[i]:
            ##print(i)
            #print(j)
            count += 1
            domainName = j[2][6]



            if j[1] not in subDomainArray:
                fqdns += 1
                subDomainArray.append(j[1])


            subdomainDepthAvgList.append(j[2][0])
            subdomainLengthAvgList.append(j[2][1])
            subdomainEntropyAvgList.append(j[2][2])
            subdomainBigramAvgList.append(j[2][3])
            domainEntropy = (j[2][4])
            domainBigram = (j[2][5])

            if j[3] not in ipArray:
                ips += 1
                ipArray.append(j[3])

            dataLengthList.append(float(j[4]))
            dataLengthTotal += float(j[4])

            if j[5] not in primarySubDomainArray:
                primaryfqdns += 1
                primarySubDomainArray.append(j[5])

            primarySubdomainDepthAvgList.append(j[2][0])
            primarySubdomainLengthAvgList.append(j[2][1])
            primarySubdomainEntropyAvgList.append(j[2][2])
            primarySubdomainBigramAvgList.append(j[2][3])
            primaryDomainEntropy = (j[2][4])
            primaryDomainBigram = (j[2][5])


            timeList.append(float(j[7]))


        ipAddress = j[0]
        if target:
            if target != ipAddress:
                break

        deltaTimeList = [j-i for i, j in zip(timeList[:-1], timeList[1:])]


        listOfArrays= [ subdomainBigramAvgList,
                        subdomainEntropyAvgList,
                        subdomainLengthAvgList,
                        subdomainDepthAvgList,
                        primarySubdomainBigramAvgList,
                        primarySubdomainEntropyAvgList,
                        primarySubdomainLengthAvgList,
                        primarySubdomainDepthAvgList,
                        dataLengthList,
                        deltaTimeList]


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
            if not i:
                i = [0] # I should investigate why empty arrays are being passed, but nah.

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
        ips,
        fqdns,
        domainEntropy,
        domainBigram,
        ))

        tempArray.extend(flatList)

        tempArray.extend((
        primaryDomainEntropy,
        primaryDomainBigram,
        dataLengthTotal
        ))

        SUPAHARRAY.append(tempArray)

    return SUPAHARRAY

def enrichedArrayToDataFrame(SUPAHARRAY, labelFlag):
    df = pd.DataFrame(SUPAHARRAY)
    cols = [
            'domainName',
            'ipAddress',
            'label',
            'dataset',
            'owner',
            'count',
            'ipd',
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
            'primarySubdomainBigramAvg',
            'primarySubdomainBigramMin',
            'primarySubdomainBigramMax',
            'primarySubdomainBigramMode',
            'primarySubdomainBigramModeCount',
            'primarySubdomainBigramEntropy',
            'primarySubdomainBigramVariation',
            'primarySubdomainBigramSkew',
            'primarySubdomainBigramKurtosis',
            'primarySubdomainEntropyAvg',
            'primarySubdomainEntropyMin',
            'primarySubdomainEntropyMax',
            'primarySubdomainEntropyMode',
            'primarySubdomainEntropyModeCount',
            'primarySubdomainEntropyEntropy',
            'primarySubdomainEntropyVariation',
            'primarySubdomainEntropySkew',
            'primarySubdomainEntropyKurtosis',
            'primarySubdomainLengthAvg',
            'primarySubdomainLengthMin',
            'primarySubdomainLengthMax',
            'primarySubdomainLengthMode',
            'primarySubdomainLengthModeCount',
            'primarySubdomainLengthEntropy',
            'primarySubdomainLengthVariation',
            'primarySubdomainLengthSkew',
            'primarySubdomainLengthKurtosis',
            'primarySubdomainDepthAvg',
            'primarySubdomainDepthMin',
            'primarySubdomainDepthMax',
            'primarySubdomainDepthMode',
            'primarySubdomainDepthModeCount',
            'primarySubdomainDepthEntropy',
            'primarySubdomainDepthVariation',
            'primarySubdomainDepthSkew',
            'primarySubdomainDepthKurtosis',
            'dataLengthAvg',
            'dataLengthMin',
            'dataLengthMax',
            'dataLengthMode',
            'dataLengthCount',
            'dataLengthEntropy',
            'dataLengthVariation',
            'dataLengthSkew',
            'dataLengthKurtosis',
            'timeDeltaAvg',
            'timeDeltaMin',
            'timeDeltaMax',
            'timeDeltaMode',
            'timeDeltaModeCount',
            'timeDeltaEntropy',
            'timeDeltaVariation',
            'timeDeltaSkew',
            'timeDeltaKurtosis',
            'primaryDomainEntropy',
            'primaryDomainBigram',
            'dataLengthTotal'
        ]
    print(len(cols))

    df.columns = cols
    if labelFlag == 1:
        df.to_csv(outputFile, mode='a', header=True, sep='\t')
    else:
        df.to_csv(outputFile, mode='a', header=False, sep='\t')

    print(df)

def fileLoad(csvName,timer, labelFlag, target):
    if timer == 'std':

        magicDictionary = enrichToDictionary(csvName)

        SUPAHARRAY = dictionaryEnricher(magicDictionary)

        enrichedArrayToDataFrame(SUPAHARRAY, labelFlag)

    else:
        with open(csvName, 'rb') as f:
            reader = csv.reader(f)
            bigArray = list(reader)

        startTime = float(bigArray[0][10])
        print("STARTING")
        print(startTime)
        timeArray = []

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

                enrichedArrayToDataFrame(SUPAHARRAY, labelFlag)
                #print(timeArray)
                timeArray = []

                labelFlag = 0
                startTime = startTime + 10

    end = time.time()
    print(end - start)


start = time.time()

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Filename of the csv to read', required=True)
parser.add_argument('-w','--write', help='Filename of the csv to write', required=True)
parser.add_argument('-t','--time', help='Time length to split by if desired', required=False, default='std')
parser.add_argument('-f','--file', help='Type of file read: "csv", "dir"', required=False, default='csv')
parser.add_argument('-l','--label', help='Label for dataset', required=True)
parser.add_argument('-d','--dataset', help='Dataset name', required=True)
parser.add_argument('-o','--owner', help='Owner name', required=True)
parser.add_argument('-a','--append', help='If set, appends to existing csv', required=False, action='store_true')
parser.add_argument('-z','--target', help='Record data for targeted IP address only', required=False)


args = vars(parser.parse_args())


csvName = args['read']
csvOne = 'output.csv'
csvTwo = 'output2.csv'


label = args['label']
dataset = args['dataset']
owner = args['owner']
target = args['target']


outputFile = args['write']

timer = args['time']

likelihoods = []
bigrams_float = []

likelihoodsMake()

if args['append']:
        print(args['append'])
        labelFlag = 0
else:
        labelFlag = 1

if args['file'] == "dir":
    print("dir")
    csvFiles = glob.glob(csvName+ "/*.*")
    for csvFile in csvFiles:
        fileLoad(csvFile, timer, labelFlag, target)

elif args['file'] == "csv":
    print("file")
    fileLoad(csvName, timer, labelFlag, target)

