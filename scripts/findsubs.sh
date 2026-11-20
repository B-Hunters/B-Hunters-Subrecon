#!/bin/sh
targetfolder=$1
domain=$2
# The Go tools live in /root/go/bin, and the Python httpx - the HTTP
# client of the platform - installs a console script of the same name
# earlier in the PATH.  The Go tool is the one that takes a list of
# hosts and answers which of them live, so it is called by its path:
# the Python one refuses to run at all ("the required dependencies were
# not installed"), and the hosts it was asked about are then never
# confirmed.
HTTPX=/root/go/bin/httpx
if [ ! -x "$HTTPX" ]; then
    HTTPX=httpx
fi
subfinder -d $domain -all -silent -o $targetfolder/subfinder.txt
vita -d $domain > $targetfolder/vita.txt
findomain -t $domain -u $targetfolder/findomain.txt
python3 /tools/Sublist3r/sublist3r.py -d $domain  -o $targetfolder/sublist3r.txt
assetfinder $domain | grep  $domain | sort -u | tee -a $targetfolder/assetfinder.txt
if [ -z "${PDCP_API_KEY}" ] || [ ${#PDCP_API_KEY} -lt 5  ]; then
    echo "PDCP_API_KEY environment variable is not set"
else
    chaos -d $domain -silent -o $targetfolder/chaos.txt
fi
cat $targetfolder/*.txt | sort -u | tee -a  $targetfolder/all.txt
cat $targetfolder/all.txt | $HTTPX -silent -o $targetfolder/httpx.txt
# cat $targetfolder/all.txt| dsieve | tee -a $targetfolder/dsieve.txt
# mksub -w /tools/level2.txt -df $targetfolder/dsieve.txt -o $targetfolder/mksub.txt