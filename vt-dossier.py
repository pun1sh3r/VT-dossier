import simplejson
import json
import urllib
import urllib2
import pprint
import sys
import time
import ast
import sys

try:
  import iocminion
except ImportError:
  print "iocminion not installed see: https://github.com/pun1sh3r/iocminion"
import argparse


iocObj = iocminion.iocMinion()

def process_list(data,desc,fd):
  if data:
    print desc
    fd.write(desc)
    for s in data:
      fd.write("\t\t%s\n" % (s))
      print "\t\t%s\n" % (s)
 

def do_request(dom,url,cat):

  browser =  urllib2.build_opener(urllib2.HTTPSHandler(debuglevel=1))
  #browser.addheaders = [('User-Agent','Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:27.0) Gecko/20100101 Firefox/27.0')]
  parameters = {cat: dom,"apikey": "your-key"}
  data = urllib.urlencode(parameters)
  res = browser.open(url+'?' +data)
  data = res.read()
  res.close()
  return data
  
def process_dom(data,outfile):
  url = 'https://www.virustotal.com/vtapi/v2/domain/report'
  for l in data.split('\n'):
    if iocObj.isInWhitelist(l):
      return
    else:
      data =  do_request(l,url,'domain')
      if bool(data) == True :
        try:
                resDict = json.loads(data)
                if resDict['response_code'] == 0 or resDict['response_code'] == -1:
                  continue
                if "detected_communicating_samples" in resDict:
                  outfile.write("report for domain: %s\n" % (l))
                  process_list(resDict['detected_communicating_samples'],"\tRelated samples:\n",outfile) 
                  if "detected_referrer_samples" in resDict:
                    process_list(resDict['detected_referrer_samples'],"\tdetected_referrer_samples:\n",outfile)
                  if 'subdomains' in resDict:
                    process_list(resDict['subdomains'],"\tSubdomains:\n",outfile)
                  if 'detected_urls' in resDict:
                    process_list(resDict['detected_urls'],"\tDetected urls:\n",outfile)
                  if 'resolutions' in resDict:
                    process_list(resDict['resolutions'],"\tIp resolutions:\n",outfile)
                else:
                  return
        except:
                print sys.exc_info()

def process_ip(data,outfile):
  #resolutions,detected_communicating_samples
  url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  for l in data.split('\n'):
    l = l.replace('\r','')
    if iocObj.isInWhitelist(l):
      return
    else:
      data =  do_request(l,url,'ip')
      outfile.write("report for ip: %s\n" % (l))
      resDict = json.loads(data)
      if resDict['response_code'] == 0 or resDict['response_code'] == -1:
        return
      
      if 'detected_communicating_samples' in resDict:
        process_list(resDict['detected_communicating_samples'],"\tMalware samples related:\n",outfile)
        if 'country' in resDict :
          outfile.write("\tCountry: " +  resDict['country'] + '\n')
        if 'as_owner' in resDict:
          outfile.write("\tOwner: " + resDict['as_owner'] + '\n' )
        if 'resolutions' in resDict:
          process_list(resDict['resolutions'],"\tIp resolutions:\n",outfile)
      else:
        return

def main():
  
  options = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,description="Just another vt-dossier")
  group = options.add_argument_group("")
  group.add_argument('--input',help='file with domain and ip data to be queried',nargs=1,required=True)
  group.add_argument('--output',help='write Results to a file',nargs=1,required=True )
  args = options.parse_args()

  if args.input and args.output:
    
    resultsFile = args.output[0]
    inputFile = args.input[0] 
    outfile = open(resultsFile,'w')

    with open(inputFile,'r') as f:	
      for entry in f:
        entry = entry.replace('\r\n','')
        isIp = iocObj.val_ip(entry)
        isDom = iocObj.val_domain(entry)
        if isIp == True:
          process_ip(entry,outfile)
        elif isDom == True:
          process_dom(entry,outfile)
          	
    outfile.close()

           
if __name__ == '__main__':
  main()
    
