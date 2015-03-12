#! /usr/bin/python

# This utility searches google for a string. It is meant to be used to search
# for Google Dorks and report back the resulting URLs
# using the pygoogle module. The default dork will search for potential
# Local File Inclusion vulnerabilities in PHP pages

__author__="r00t5"
__date__ ="$Mar 1, 2015 Mar 1, 2015 6:42:53 PM$"

from pygoogle import pygoogle
from commands import *
from optparse import OptionParser
import os

current_dir = os.path.dirname(os.path.realpath(__file__))
parser = OptionParser()
parser.add_option("-p", "--pages", dest="numPages", default=5,
                  help="The number of result pages to return")
parser.add_option("-g", "--google-dork", dest="theDork", default="inurl:\".php?page=\"",
                  help="The number of result pages to return")
parser.add_option("-o", "--output-only", dest="outFile", default= False,
                  help="Only save results to the given file, No further action.")                  
parser.add_option("-d", "--debug", dest="debugRun", default= False,
                  help="Debug the tool without poisoning or exploiting the host")
                  
(options, args) = parser.parse_args()
fk =7

if options.debugRun not in ["t","True","true","TRUE"]:
    g = pygoogle(options.theDork)
    g.pages = options.numPages #Set to the number of result url pages to return from google
    fk = g.get_result_count()
    print '*Found %s results*'%(fk)
    # Handle case where we want to use the host for 
    urls = g.get_urls()
else:
    print '*Debug test %s*'%(fk)
    urls = ["http://localhost:8087"]
    
# Handle case where we only want the results to a file.
if options.outFile in ["t","True","true","TRUE"]:
    file = open(options.outFile, "w")
    for url in urls:
        file.write("%s\n" % url)
    print "File saved to: %s" % options.outFile
    exit(0)
    
for url in urls:
    print "Checking %s for LoFiInc" % url
    # Call lfiHunter with potential URL
    cmd = "python %s/lfiVulnHunter.py --url=\"%s\"" % (current_dir,url)
    if options.debugRun is not None:
        cmd += " -d 1" # add the debug var to the command
        
    print getoutput(cmd)