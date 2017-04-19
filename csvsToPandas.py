import argparse
import csv
import glob
import math
import pandas as pd
import time
from collections import Counter
from collections import defaultdict
from scipy import stats


def dictionaryMaker(csvOne, csvTwo):
    f = open(csvOne)
    csv_f = csv.reader(f)
    domain2ip = defaultdict(dict)

    for row in csv_f:
        if len(row[0]) < 25:
            pass


        else:

            try:
                a = (row[0].split("\t"))
            except:
                break
            # print(a)
            # This fails sometimes when the packet capture gets corrupted, we wind up having one and a half
            # Then the call for a[2] is

            try:
                b = a[2].split(".")
            except:
                break
            if b[-1].isdigit() or b == []:
                # then its an ip, skip it
                # perhaps should add ip detection
                # print(b[-1])
                pass
            else:
                domain2ip[a[1]] = [a[2]]

    f = open(csvTwo)
    csv_f = csv.reader(f)

    for row in csv_f:
        if len(row[0]) < 25:
            pass


        else:
            try:
                a = row[0].split("\t")

            except:
                break
            # print(a)
            try:
                b = a[2].split(".")
            except:
                break
            if b[-1].isdigit() or b == []:
                # then its an ip, skip it
                # perhaps should add ip detection
                # print(b[-1])
                pass
            else:
                domain2ip[a[1]] = [a[2]]

    return domain2ip


def likelihoodsMake():
    likelihood_file = "likelihoods.txt"
    bigram_file = "bigrams.txt"

    if not bigrams_float:
        bigrams = open(bigram_file, "r")
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
        for k in range(len(field) - 1):
            this_ltr = field[k]

            next_ltr = field[k + 1]
            this_idx = ord(this_ltr) - ord('a')

            next_idx = ord(next_ltr) - ord('a')

            field_likelihood = bigrams_float[this_idx][next_idx] * 2 * len(field)
        return field_likelihood
    else:
        return 0


def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


def domainEnrich(domainNameFull):
    subdomainName = domainNameFull.split(".")[:-2]

    subdomainNameJoined = (''.join(subdomainName)).lower()

    domainName = domainNameFull.split(".")[-2].lower()

    domainNameJoined = ('.'.join(domainNameFull.split(".")[-2:])).lower()

    subdomainDepth = len(subdomainName)
    subdomainLength = len(subdomainNameJoined)

    subdomainEntropy = entropy(subdomainNameJoined)

    subdomainNameJoined = subdomainNameJoined

    field = subdomainNameJoined.translate(None, '0123456789-')  # PROBLEM CHILD
    subdomainBigram = bigramQuery(field)

    domainEntropy = entropy(domainName)

    field = domainName.translate(None, '0123456789-')  # PROBLEM CHILD
    domainBigram = bigramQuery(field)
    return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram,
            subdomainName, domainNameJoined]


def enrichToDictionary(csvName):
    with open(csvName, 'rb') as f:
        reader = csv.reader(f)
        bigArray = list(reader)

    magicDictionary = {}

    for i in bigArray:

        # print(i)
        # We need to create domain fields real quick
        newI = i

        if domain2ip[i[2]] != {}:
            if domain2ip[i[2]][0].split(".")[-1].isdigit():

                print("WE IN HERE")

                subdomainName = ''
                subdomainDepth = 0
                subdomainLength = 0
                subdomainEntropy = 0
                subdomainBigram = 0
                domainEntropy = 0
                domainBigram = 0

            else:
                domainNameFull = domain2ip[i[2]][0]

                enriched = domainEnrich(domainNameFull)
                # return [subdomainDepth, subdomainLength, subdomainEntropy, subdomainBigram, domainEntropy, domainBigram, subdomainName, domainNameJoined]
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

        try:
            bytesPerFrameFrom = float(i[5]) / float(i[4])
        except:
            bytesPerFrameFrom = 0

        try:
            bytesPerFrameTo = float(i[7]) / float(i[6])
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

            # print(magicDictionary[dictKey])
            # print("AAA")
            # print(i)
            magicDictionary[dictKey].append(newI)




        else:

            magicDictionary[dictKey] = [newI]

    return magicDictionary


def dictionaryEnricher(magicDictionary, DNSdict):
    SUPAHARRAY = []

    for i in magicDictionary:


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


        framesFromTotal = 0
        bytesFromTotal = 0
        framesToTotal = 0
        bytesToTotal = 0
        framesTotalTotal = 0
        bytesTotalTotal = 0

        for j in magicDictionary[i]:
            #print(j)
            count += 1
            domainName = j[4]
            if j[5] not in subDomainArray:
                fqdns += 1
                subDomainArray.append(j[5])

            domainBigram = j[6]
            domainEntropy = j[7]

            try:
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
                timeList.append(float(j[20]))
            except:
                continue

        ipAddress = j[2]
        if target:
            if target != ipAddress:
                continue

        domainLabel = label

        if ipLabel:
            if domainName == "none":
                domainLabel = "ipOnly"

        if labelList:

            if labelList == domainName.split(".")[-1]:
                domainLabel = "Good"

        if domainName.split(".")[-1].lstrip().rstrip() == "bluenet" or domainName.split(".")[-1].lstrip().rstrip() == "simnet":
            continue

        try:
            if ipAddress.split(".")[1].lstrip().rstrip() == "1" or ipAddress.split(".")[0].lstrip().rstrip() != "10":
                continue
        except:
            continue

        if protocol:
            protocolLabel = protocol
        else:
            protocolLabel = 0

        if malware:
            malwareLabel = malware
        else:
            malwareLabel = 0

        if sleep:
            sleepLabel = sleep
        else:
            sleepLabel = 0

        if jitter:
            jitterLabel = jitter
        else:
            jitterLabel = 0


        deltaTimeList = [j - i for i, j in zip(timeList[:-1], timeList[1:])]

        listOfArrays = [subdomainBigramAvgList,
                        subdomainEntropyAvgList,
                        subdomainLengthAvgList,
                        subdomainDepthAvgList,
                        framesFromList,
                        bytesFromList,
                        bytesPerFrameFromList,
                        framesToList,
                        bytesToList,
                        bytesPerFrameToList,
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
        for k in listOfArrays:
            listOfListOfFeatures = [[]] * 9
            if k and k[0] != 0:

                listOfListOfFeatures[0] = float(sum(k) / (len(k)))  # Average
                listOfListOfFeatures[1] = min(k)  # min
                listOfListOfFeatures[2] = max(k)  # max
                listOfListOfFeatures[3] = stats.mode(k)[0][0]  # mode
                listOfListOfFeatures[4] = stats.mode(k)[1][0]  # mode count
                if listOfListOfFeatures[4] == 1:  # if modecount = 1
                    listOfListOfFeatures[4] = 0  # set = 0
                listOfListOfFeatures[5] = stats.entropy(k)  # entropy
                if math.isnan(listOfListOfFeatures[5]):  # if is not a number
                    listOfListOfFeatures[4] = 0  # set = 0
                    listOfListOfFeatures[5] = 0  # set = 0
                listOfListOfFeatures[6] = stats.variation(k)  # variation
                if math.isnan(listOfListOfFeatures[6]):  # if is not a number
                    listOfListOfFeatures[6] = 0  # set = 0
                listOfListOfFeatures[7] = stats.skew(k)  # skew
                listOfListOfFeatures[8] = stats.kurtosis(k)  # kurtosis
            else:
                listOfListOfFeatures = [0] * 9

            statisticsArray.append(listOfListOfFeatures)




        #print(domainName)
        try:
            DNSarray = DNSdict[domainName]
            #print(DNSarray)
        except:
            #print("NODNS")
            DNSarray = [0] *61
        #print(len(DNSarray))

        flatList = [item for sublist in statisticsArray for item in sublist]

        tempArray.extend((
            domainName,
            ipAddress,
            domainLabel,
            protocolLabel,
            malwareLabel,
            sleepLabel,
            jitterLabel,
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
            bytesTotalTotal,
        ))

        #print(len(tempArray))

        #flatList = [item for sublist in DNSarray for item in sublist]
        tempArray.extend(DNSarray)

        dnsToTcpRatio = DNSarray[0]/count

        tempArray.extend([dnsToTcpRatio])


        #print(len(tempArray))


        SUPAHARRAY.append(tempArray)

    return SUPAHARRAY

def DNSenrichToDictionary(csvName):
    with open(csvName, 'rb') as f:
        reader = csv.reader(f)
        bigArray = list(reader)
    magicDictionary = {}
    for i in bigArray:
        splitArray = i[0].split("\t")

        dnsRespNameFull = splitArray[1]
        try:
            enriched = domainEnrich(dnsRespNameFull)
        except: #wireshark errors like truncated ddomain names
            break

        if splitArray[4] != "":
            dnsRespPrimaryNameFull = splitArray[4]

            enrichedPrimary = domainEnrich(dnsRespPrimaryNameFull)

            splitArray.insert(5, enrichedPrimary)
        else:
            splitArray.insert(5, [0] * 7)  # if there is no primaryResponseName, make everything zeros
        splitArray.insert(2, enriched)

        dictKey = splitArray[0] + "x" + enriched[-1]
        if dictKey in magicDictionary:

            magicDictionary[dictKey].append(splitArray)


        else:

            magicDictionary[dictKey] = [splitArray]
    return magicDictionary


def DNSdictionaryEnricher(magicDictionary):
    DNSSUPAHARRAY = []


    for i in magicDictionary:


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

        primarySubdomainDepthAvgList = []
        primarySubdomainLengthAvgList = []
        primarySubdomainEntropyAvgList = []
        primarySubdomainBigramAvgList = []
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

            count += 1
            domainName = j[1]

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

        ipAddress = j[2]
        if target:
            if target != ipAddress:
                break

        domainLabel = label

        if ipLabel:
            if domainName == "none":
                domainLabel = "ipOnly"

        if labelList:
            if labelList == domainName.split(".")[-1]:
                domainLabel = "Good"

        if protocol:
            protocolLabel = protocol
        else:
            protocolLabel = 0

        if malware:
            malwareLabel = malware
        else:
            malwareLabel = 0

        if sleep:
            sleepLabel = sleep
        else:
            sleepLabel = 0

        if jitter:
            jitterLabel = jitter
        else:
            jitterLabel = 0

        deltaTimeList = [j - i for i, j in zip(timeList[:-1], timeList[1:])]

        listOfArrays = [
                        subdomainDepthAvgList,
                        subdomainLengthAvgList,
                        subdomainEntropyAvgList,
                        subdomainBigramAvgList,
                        #primarySubdomainBigramAvgList,
                        #primarySubdomainEntropyAvgList,
                        #primarySubdomainLengthAvgList,
                        #primarySubdomainDepthAvgList,
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
        for k in listOfArrays:
            listOfListOfFeatures = [[]] * 9

            if not k:
                k = [0]  # I should investigate why empty arrays are being passed, but nah.
            listOfListOfFeatures[0] = float(sum(k) / (len(k)))  # Average
            listOfListOfFeatures[1] = min(k)  # min
            listOfListOfFeatures[2] = max(k)  # max
            listOfListOfFeatures[3] = stats.mode(k)[0][0]  # mode
            listOfListOfFeatures[4] = stats.mode(k)[1][0]  # mode count
            if listOfListOfFeatures[4] == 1:  # if modecount = 1
                listOfListOfFeatures[4] = 0  # set = 0
            listOfListOfFeatures[5] = stats.entropy(k)  # entropy
            if math.isnan(listOfListOfFeatures[5]):  # if is not a number
                listOfListOfFeatures[4] = 0  # set = 0
                listOfListOfFeatures[5] = 0  # set = 0
            listOfListOfFeatures[6] = stats.variation(k)  # variation
            if math.isnan(listOfListOfFeatures[6]):  # if is not a number
                listOfListOfFeatures[6] = 0  # set = 0
            listOfListOfFeatures[7] = stats.skew(k)  # skew
            listOfListOfFeatures[8] = stats.kurtosis(k)  # kurtosis
            statisticsArray.append(listOfListOfFeatures)

        flatList = [item for sublist in statisticsArray for item in sublist]

        domainName = ('.'.join(domainName.split(".")[-2:])).lower()

        tempArray.extend((
            domainName,
            count,
            fqdns,
            primaryfqdns,
            ips,
        ))
        tempArray.extend(flatList)

        tempArray.extend((
            primaryDomainEntropy,
            primaryDomainBigram,
            dataLengthTotal
        ))

        DNSSUPAHARRAY.append(tempArray)

    return DNSSUPAHARRAY


def enrichedArrayToDataFrame(SUPAHARRAY, labelFlag):
    df = pd.DataFrame(SUPAHARRAY)
    cols = [
        'domainName',
        'ipAddress',
        'label',
        'protocolLabel',
        'malwareLabel',
        'sleepLabel',
        'jitterLabel',
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
        'timeDeltaAvg',
        'timeDeltaMin',
        'timeDeltaMax',
        'timeDeltaMode',
        'timeDeltaModeCount',
        'timeDeltaEntropy',
        'timeDeltaVariation',
        'timeDeltaSkew',
        'timeDeltaKurtosis',
        'framesFromTotal',
        'bytesFromTotal',
        'framesToTotal',
        'bytesToTotal',
        'framesTotalTotal',
        'bytesTotalTotal',
        'count',
        'fqdns',
        'primaryfqdns',
        'ips',
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
        """
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
        """
        'dnsDataLengthAvg',
        'dnsDataLengthMin',
        'dnsDataLengthMax',
        'dnsDataLengthMode',
        'dnsDataLengthCount',
        'dnsDataLengthEntropy',
        'dnsDataLengthVariation',
        'dnsDataLengthSkew',
        'dnsDataLengthKurtosis',
        'dnsTimeDeltaAvg',
        'dnsTimeDeltaMin',
        'dnsTimeDeltaMax',
        'dnsTimeDeltaMode',
        'dnsTimeDeltaModeCount',
        'dnsTimeDeltaEntropy',
        'dnsTimeDeltaVariation',
        'dnsTimeDeltaSkew',
        'dnsTimeDeltaKurtosis',
        'primaryDomainEntropy',
        'primaryDomainBigram',
        'dnsDataLengthTotal',
        'dnsToTcpRatio'
    ]

    df.columns = cols
    if labelFlag == 1:
        df.to_csv(outputFile, mode='a', header=True, sep='\t')
    else:
        df.to_csv(outputFile, mode='a', header=False, sep='\t')

    print(df)


def fileLoad(csvName, DNScsvName, timer, labelFlag):
    if timer == 'std':

        DNSmagicDictionary = DNSenrichToDictionary(DNScsvName)
        DNSSUPAHARRAY = DNSdictionaryEnricher(DNSmagicDictionary)
        #print(DNSSUPAHARRAY)

        DNSDict = {item[0]: item[1:] for item in DNSSUPAHARRAY}

        magicDictionary = enrichToDictionary(csvName)
        SUPAHARRAY = dictionaryEnricher(magicDictionary, DNSDict)
        #print(SUPAHARRAY)


        #print(DNSSUPAHARRAY)


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
            # print(i)
            if startTime + float(timer) > float(i[10]):
                timeArray.append(i)

            else:
                with open("tmp.csv", "w") as f:
                    writer = csv.writer(f)
                    writer.writerows(timeArray)
                magicDictionary = enrichToDictionary("tmp.csv")

                SUPAHARRAY = dictionaryEnricher(magicDictionary)

                enrichedArrayToDataFrame(SUPAHARRAY, labelFlag)
                # print(timeArray)
                timeArray = []

                labelFlag = 0
                startTime += 10

    end = time.time()
    print(end - start)


start = time.time()

parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-r", "--read", help='Filename of the csv to read', required=True)
parser.add_argument("-rd", "--readDNS", help='Filename of the DNS csv to read', required=True)

parser.add_argument('-w', '--write', help='Filename of the csv to write', required=True)
parser.add_argument('-t', '--time', help='Time length to split by if desired', required=False, default='std')
parser.add_argument('-f', '--file', help='Type of file read: "csv", "dir"', required=False, default='csv')
parser.add_argument('-l', '--label', help='Label for dataset', required=True)

parser.add_argument('-m', '--malware', help='Record data for targeted IP address only', required=False)
parser.add_argument('-p', '--protocol', help='Record data for targeted IP address only', required=False)
parser.add_argument('-s', '--sleep', help='Record data for targeted IP address only', required=False)
parser.add_argument('-j', '--jitter', help='Record data for targeted IP address only', required=False)

parser.add_argument('-d', '--dataset', help='Dataset name', required=True)
parser.add_argument('-o', '--owner', help='Owner name', required=True)
parser.add_argument('-a', '--append', help='If set, appends to existing csv', required=False, action='store_true')
parser.add_argument('-z', '--target', help='Record data for targeted IP address only', required=False)


parser.add_argument('-y', '--labelList', help='label ._____ as Good', required=False)
parser.add_argument('-x', '--ipLabel', help='ipOnly label', required=False, action='store_true')

args = vars(parser.parse_args())

csvName = args['read']
DNScsvName = args['readDNS']
csvOne = 'output.csv'
csvTwo = 'output2.csv'

label = args['label']
protocol = args['protocol']
malware = args['malware']
sleep = args['sleep']
jitter = args['jitter']


dataset = args['dataset']
owner = args['owner']
target = args['target']

labelList = args['labelList']
ipLabel = args['ipLabel']

outputFile = args['write']

timer = args['time']

likelihoods = []
bigrams_float = []

likelihoodsMake()

domain2ip = dictionaryMaker(csvOne, csvTwo)

if args['append']:
    print(args['append'])
    labelFlag = 0
else:
    labelFlag = 1

if args['file'] == "dir":
    print("dir")
    csvFiles = glob.glob(csvName + "/*.*")
    for csvFile in csvFiles:
        fileLoad(csvFile, timer, labelFlag)

elif args['file'] == "csv":
    fileLoad(csvName, DNScsvName, timer, labelFlag)
