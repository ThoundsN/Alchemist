#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import base64
import math
import sys
import re

# usage: Open Burp, navigate to proxy history, ctrl-a to select all records, right click and "Save Items" as an .xml file. 
# python burplist.py burprequests.xml
# output is saved to raw_wordlist.txt

cleansing_regexes = list((
    "[\\!(,%]",  # Ignore noisy characters
    ".{50,}",  # Ignore lines with more than 100 characters (overly specific)
    "[0-9]{3,}",  # Ignore lines with 4 or more consecutive digits (likely an id)
    "[0-9]{3,}\Z",  # Ignore lines where the last 3 or more characters are digits (likely an id)
    "[a-z0-9]{32}",  # Likely MD5 hash or similar
    "[0-9]+[A-Z0-9]{5,}",  # Number followed by 5 or more numbers and uppercase letters (almost all noise)
    "/.*/.*/.*/.*/.*/.*/",  # Ignore lines more than 6 directories deep (overly specific)
    "[0-9A-Za-z_]{8}-[0-9A-Za-z_]{4}-[0-9A-Za-z_]{4}-[0-9A-Za-z_]{4}-[0-9A-Za-z_]{12}",  # Ignore UUIDs
    "[0-9]+[a-zA-Z]+[0-9]+[a-zA-Z]+[0-9]+",  # Ignore multiple numbers and letters mixed together (likley noise)
    "\.(png|jpg|jpeg|gif|svg|bmp|ttf|avif|wav|mp4|aac|ajax|css|all|woff)\Z",  # Ignore low value filetypes
    "^\Z"  # Ignores blank lines
))

matching_regexes = dict(path="/|\?|&|=",
                        raw_content="/|\?|&|=|_|-|\.|\+|:| |\n|\r|\t|\"|\Z|<|>|\{|\}|\[|\]|`|~|!|@|\#|\$|;|,|\(|\)|\*|\^|\\\\|\|")


def calcEntropy(string):
    # "Calculates the Shannon entropy of a string"
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

def isUsefulWord(word):
    if word.isnumeric():
        return None
    for regex in cleansing_regexes:
        if re.search(regex,word):
            return None
    entropy_value = calcEntropy(word)
    if entropy_value <= 4.25:
        return word


if __name__ == '__main__':
    burplog_infile = sys.argv[1]
    wordlist_outfile = sys.argv[2]

    tree = ET.parse(burplog_infile)
    root = tree.getroot()
    raw_wordlist = set()
    for i in root:

        # path  
        raw_wordlist |= set(re.split(matching_regexes['path'], i[6].text))

        # base64 reqeust
        raw_wordlist |= set(re.split(matching_regexes['raw_content'],
                             base64.b64decode(i[8].text).decode('ascii')))

        # base64 response
        if i[12].text is not None:
            raw_wordlist |= set(re.split(
                matching_regexes['raw_content'],
                base64.b64decode(i[12].text).decode('ascii')))


    final_wordlist = set()

    for word in raw_wordlist:
        if isUsefulWord(word):
            final_wordlist.add(word)


    with open(wordlist_outfile, 'w') as f:
        for item in final_wordlist:
            f.write("%s\n" % item)
