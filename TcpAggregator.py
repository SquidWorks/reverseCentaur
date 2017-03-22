import os
import argparse
import operator
import time
import csv
import glob
import pandas as pd


parser = argparse.ArgumentParser(description="provide the parameters to make the file run")
parser.add_argument("-R", "--readDirectory", help='Description for readFile argument', required=True)
parser.add_argument('-w','--write', help='Description for live argument', required=True)


args = vars(parser.parse_args())

start = time.time()

directoryName = args['readDirectory']
csvName = args['write']
flag = 1

count = 1

allFiles = glob.glob(directoryName+ "/*.csv")



fout=open("temp.csv","w")
for file in allFiles:
    for line in open(file):
         fout.write(line)

fout.close()

end = time.time()
print(end - start)



reader = csv.reader(open("temp.csv"), delimiter=',')

def sort_foo(x):
    print(x[10])
    return x[10]


sortedlist = sorted(reader, key=sort_foo)    # 0 specifies according to first column we want to sort
print(sortedlist)

#now write the sorte result into new CSV file
with open(csvName, "wb") as f:
    fileWriter = csv.writer(f, delimiter='\t')
    for row in sortedlist:

        fileWriter.writerow(row)


fout.close()


end = time.time()
print(end - start)