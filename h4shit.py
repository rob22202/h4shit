#!/usr/bin/python

import csv, urllib2, re, sys, getopt

def main(argv):
        inputfile = ''
        outputfile = ''
        goodfile = '/scripts/good_hashes.txt'
        badfile = '/scripts/bad_hashes.txt'

        print "*************************************************"
        print ""
        print "  _     _  _       _     _ _                     "
        print " | |__ | || |  ___| |__ (_) |_       _ __  _   _ "
        print " | '_ \| || |_/ __| '_ \| | __|     | '_ \| | | |"
        print " | | | |__   _\__ \ | | | | |_   _  | |_) | |_| |"
        print " |_| |_|  |_| |___/_| |_|_|\__| (_) | .__/ \__, |"
        print "                                    |_|    |___/ "
        print ""
        print "*************************************************"

        try:
                opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
        except getopt.GetoptError:
                print 'h4shit.py -i <inputfile>'
                sys.exit(2)

        for opt, arg in opts:
                if opt == '-h':
                        print 'h4shit.py -i <inputfile>'
                        sys.exit()
                elif opt in ("-i", "--ifile"):
                        inputfile = arg
                elif opt in ("-o", "--ofile"):
                        outputfile = arg

        if inputfile == "":
                print "Usage: h4shit.py -i <inputfile>"
                print "No input file specified"
                print ""
                sys.exit(2)

        print ""
        print "Looking up hashes in:  " + inputfile
        print "Using good hash list from:  " + goodfile
        print "Using bad hash list from:  " + badfile
        print ""
        print "Output excludes files that are on the local 'good list'"
        print "and those that VirusTotal reports no vendors detecting as malware"
        print ""
        print "Running but no results displayed unless a potentially bad or unknown result is obtained..."

        inputdata = open(inputfile, "r")
        input_hash_file = csv.reader((line.replace('\0','') for line in inputdata), delimiter="\t")
        good_hash_file = csv.reader(open('./good_hashes.txt', 'r'),delimiter='\t')
        bad_hash_file = csv.reader(open('./bad_hashes.txt', 'r'),delimiter='\t')
        good_hashes = []
        for row in good_hash_file:
                good_hashes.append(row[1])
        bad_hashes = []
        for row in bad_hash_file:
                bad_hashes.append(row[1])
        for input_hashes_row in input_hash_file:
                try:
                        in_hash = input_hashes_row[2]
                        in_filename = input_hashes_row[1]
                        vt_result = ""
                        cymru_result = ""
                        te_result = ""
                        if in_hash in good_hashes:
                                in_good = "Yes"
                        else:
                                in_good = "No"
                                if len(in_hash) == 32:
                                        vt_result = vt_lookup(in_hash)
                        if in_hash in bad_hashes:
                                in_bad = "Yes"
                        else:
                                in_bad = "No"

                        if in_good != "Yes" and len(in_hash) == 32 and in_filename != "Name":
                                padded_filename = in_filename.ljust((30-len(in_filename))," ")
                                if str("0 /") not in vt_result:
                                        print padded_filename + "\t" + in_hash + "   Good_List: " + in_good + "   Bad_List: " + in_bad + "   VirusTotal_Result: " + vt_result
                except KeyboardInterrupt:
                        print ""
                        print "Process killed by user!"
                        sys.exit(2)

def vt_lookup(in_hash):
        vt_url = "https://www.virustotal.com/en/file/" + in_hash + "/analysis/"
        vt_request = urllib2.Request(vt_url)
        vt_request.add_header("User-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.72 Safari/537.36")
        vt_result = urllib2.urlopen(vt_request)
        vt_result_string = (str(vt_result.read()))
        regex = re.compile('\\d+\\s+\\/\\s+\\d+', re.IGNORECASE)
        regex_result = str(re.findall(regex,vt_result_string))
        vt_output = str(regex_result)[2:-2]
        if vt_output != "":
                return  vt_output
        else:
                return "NO_DATA"

if __name__ == "__main__":
        main(sys.argv[1:])
