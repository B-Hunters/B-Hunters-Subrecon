#!/bin/sh
targetfolder=$1
domain=$2
subfinder -d $domain -all -silent -o $targetfolder/subfinder.txt
vita -d $domain > $targetfolder/vita.txt
findomain -t $domain -u $targetfolder/findomain.txt
python3 /tools/Sublist3r/sublist3r.py -d $domain  -o $targetfolder/sublist3r.txt
assetfinder $domain | grep  $domain | sort -u | tee -a $targetfolder/assetfinder.txt
chaos -d $domain -silent -o $targetfolder/chaos.txt
cat $targetfolder/*.txt | sort -u | tee -a  $targetfolder/all.txt
cat $targetfolder/all.txt | httpx -silent -o $targetfolder/httpx.txt
# cat $targetfolder/all.txt| dsieve | tee -a $targetfolder/dsieve.txt
# mksub -w /tools/level2.txt -df $targetfolder/dsieve.txt -o $targetfolder/mksub.txt