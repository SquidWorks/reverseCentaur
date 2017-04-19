# reverseCentaur

Reverse Centaur is a fully featured framework for ingesting packet captures, enriching the data with various techniques, and creating features for use in machine learning. It is a hacked together single threaded series of scripts. 

# How Does It Work

xxxDiagramxxx 

By using human analysts to augment semi-supervised machine learning, defenders can automate the classification process, creating a feedback loop which lowers workload while increasing prediction accuracy. The human analyst is presented with outlier domains, investigates, applies labels to a portion of the traffic, and blocks malicious domains. These labels are then incorporated back into the prediction model and used to classify future domains. Over time, the human-machine team will become increasingly accurate. 

# Future Work 

All of these things are a project in themselves, and you should choose one. If you are interested, email me at d.m.devey@gmail.com. 
- [ ] Data Cleaning and Enrichments
- [ ] Build Datasets for Training and Validation
- [ ] Optimize Outlier Detection
- [ ] Optimize Supervised Machine Learning
- [ ] Design Analyst Experience
- [ ] Build Analyst Experience
- [ ] Streamline Ingest to Analysis Process
- [ ] Convert Program to Use a Structured Database
- [ ] Optimize Speed

# How To Use It

## pcapToCsvs.py
Takes a packet capture or directory of packet captures as input, then runs tshark scripts to extract the required conversation data. This data is then written to csv files.

#### Usage For Single File: 

python pcapToCsvs.py -r captureName.pcap -w tcpOutput.csv -wd dnsOutput.csv

## csvsToPandas.py

Takes the csv files created by pcapToCsvs as input, then performs a variety of enrichments, listed below.
* tcpSubdomainBigram
* tcpSubdomainEntropy
* tcpSubdomainLength
* tcpSubdomainDepth
* tcpframesFrom
* tcpbytesFrom
* tcpbytesPerFrame
* tcpframesTo
* tcpbytesTo
* tcpbytesPerFrame
* tcpAccessTimeDelta
* dnsSubdomainBigram
* dnsSubdomainEntropy
* dnsSubdomainLength
* dnsSubdomainDepth
* dnsDataLength
* dnsAccessTimeDelta
* Along with various counters and booleans.


For each of the listed features, we calculate these statistics. 

* mean
* min
* max
* mode
* modeCount
* entropy
* variation
* skew
* kurtosis

Then we take all of these features and make one csv for importing into a machine learning program. 
           
#### Usage to Create Standard Features:

python csvTcpToPandasMod.py -r tcpOutput.csv -rd dnsOutput.csv -w finalFeatures.csv -l unlabled -d cdx2017usna -o Devey 

#### Usage to Create Features Split By Time Period (30 minutes):

python csvTcpToPandasMod.py -r tcpOutput.csv -rd dnsOutput.csv -w finalFeatures.csv -l unlabled -d cdx2016usna -o Devey -t 1800

