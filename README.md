# reverseCentaur

Reverse Centaur is a fully featured framework for ingesting packet captures, enriching the data with various techniques, and creating features for use in machine learning. It is a hacked together single threaded series of scripts, that winds up being surprisingly effective.

## pcapToTcpCsv.py
Takes a packet capture or directory of packet captures as input, cleans up the data, splits them into manageable sizes, then runs tshark scripts to extract the required conversation data. This data is then written to a csv file.

#### Usage For Single File: 

python pcapToTcpCsv.py -r exampleInput.pcapng -w exampleOutput.csv


#### Usage For Directory:

python pcapToTcpCsv.py -r exampleDirectoryName -w exampleOutput.csv -t dir


## csvTcpToPandas.py

Takes the csv file created by pcapToTcpCsv as input, then performs a variety of enrichments, listed below.
* subdomainBigram
* subdomainEntropy
* subdomainLength
* subdomainDepth
* framesFrom
* bytesFrom
* bytesPerFrame
* framesTo
* bytesTo
* bytesPerFrame

For each of these features, we calculate these statistics. 

* mean
* min
* max
* mode
* modeCount
* entropy
* variation
* skew
* kurtosis

Then we take all of these features and make one giant csv for importing into a machine learning program.
           
#### Usage to Create Standard Features:

python csvTcpToPandas.py -r exampleOutput.csv -w exampleFeatures.csv -l labeName -d dataset -o owner


#### Usage to Create Features by Time Period (30 seconds):

python csvTcpToPandas.py -r exampleOutput.csv -w exampleFeatures.csv -t 30 -l labelName -d dataset -o owner

