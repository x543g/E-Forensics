#!/usr/local/bin/fish
function installer
    if test (which figlet); sleep 0.1;else;sudo apt install -y figlet;end
    if test (which rg); sleep 0.1;else;sudo apt install -y ripgrep;end
    if test (which lolcat); sleep 0.1;else;sudo apt install -y lolcat;end
    if test (which exiftool); sleep 0.1;else;sudo apt install -y exiftool;end
    if test -f digital.flf; sleep 0.1;else
        command curl -s "https://raw.githubusercontent.com/xero/figlet-fonts/master/Digital.flf" -o digital.flf
        end 
    if test -f cyberlarge.flf; sleep 0.1;else
        command curl -s "https://raw.githubusercontent.com/xero/figlet-fonts/master/Cyberlarge.flf" -o cyberlarge.flf
        echo no
        end 
end
function helper
    echo "use: fish E-forensics.fish /location/email.eml"
end
function logo
    clear
    figlet -w 140 -f cyberlarge.flf "E-forensics" | lolcat
    echo "                        email source forensics tool that extracts key information"
    echo ""
end
#install checker

    installer

#arg checker

if test "$argv[1]" = "--help"
    logo
    helper
    exit 1
    end
if test ! -n "$argv[1]"
    logo
    helper
    exit 1
    end
#testing if file contains email strings

if test (rg -N '^Subject: ' "$argv[1]" |cut -f2 -d ":" |sed 's/^ //')
    set var_checksum "ok"
    else
    echo file is not a valid type, exiting...
    exit 1
    end

#main function of extractions

if test $var_checksum = "ok"
    logo
    figlet -w 140 -f digital.flf "Details" | lolcat
    echo "Dkim Status     :" (rg -N -o 'dkim=(pass|fail)' "$argv[1]" |strings |cut -f1 -d " " |head -n1 |sed 's/dkim=//')
    echo "Dmarc Status    :" (rg -N -o 'dmarc=.*$' "$argv[1]" |tr -d ";" |sed s'/dmarc=//' |cut -f1 -d " " |head -n1)
    echo "SPF Status      :" (rg -N -o 'spf=(none|pass|fail)' "$argv[1]" |strings |sed 's/spf=//' |cut -f1 -d " " |head -n1)
    echo "DTG             :" (rg -N -o '(Mon|Tue|Wed|Thu|Fri|Sat|Sun).*[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$argv[1]" |head -n1)
    echo "Dkim Signature  :" (rg -N '^DKIM-Signature: ' "$argv[1]" |tr -d ";" |sed 's/DKIM-Signature://' |sed 's/^ //' |head -n1)
    echo "Dkim Header     :" (rg -N -o '(header.d=[a-zA-Z0-9]{4,30}\.(org|com|net|xyz|info|ltd|uk|net|co|cc)|d=[a-zA-Z0-9]{4,30}\.(org|com|net|xyz|info|ltd|uk|net|co|cc))' "$argv[1]" |strings |sed 's/header.d=//' |head -n1 |sed 's/d=//')
    echo "Dkim H-Source   :" (rg -N -o 'header.s=.* ' "$argv[1]" |strings |sed 's/header.s=//' |cut -f1 -d " " |head -n1)
    echo "Dkim Header ID  :" (rg -N -o 'header.b=.*;' "$argv[1]" |tr -d ";" |sed 's/header.b=//' |tr -d '"' |sed 's/\///' |cut -f1 -d " " |head -n1)
    echo "Sender Details  :" (rg -N -o '^Sender:  <.*>' "$argv[1]" |sed 's/Sender:  <//' |tr -d ">" |head -n1)
    if test (rg -N -o '^Message-Id: <.*>' "$argv[1]" |sed 's/Message-Id: <//' |tr -d ">" |head -n1)
    echo "Message ID      :" (rg -N -o '^Message-Id: <.*>' "$argv[1]" |sed 's/Message-Id: <//' |tr -d ">" |head -n1)
    else
    echo "Message ID      :" (rg -N -o 'id .*( |;)' "$argv[1]" |sed 's/id //' |tr -d ">" |head -n1 |tr -d ";")
    end
    echo "Recived from    :" (rg -N '^From: ' "$argv[1]" |sed 's/From: //' |tr -d ">" |tr -d "<" |rg -No "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" |head -n1)
    echo "X-PHP-Filename  :" (rg -N '^X-PHP-Filename: ' "$argv[1]" |cut -f2 -d " " |sed 's/^ //' |head -n1)
    echo "X-PHP-Script    :" (rg -N '^X-PHP-Script: ' "$argv[1]" |cut -f2 -d " " |sed 's/^ //' |head -n1)
    echo "Recieved Subject:" (rg -N '^Subject: ' "$argv[1]" |cut -f2 -d ":" |sed 's/^ //')
    echo "Recieved details:" (rg -N '^Received: from' "$argv[1]" |sed 's/Received: from//' |sed 's/^ //' |rg -o '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]' |rg -N -o '.*\.(org|com|net|xyz|info|ltd|uk|net|co|cc)' |sort -u |head -n1)
    echo "Delivered to    :" (rg -N '^Delivered-To:' "$argv[1]" |sed 's/Delivered-To://' |sed 's/^ //' |head -n1)
    echo "Return Path     :" (rg -N '^Return-Path: <' "$argv[1]" |sed 's/Return-Path: <//' |tr -d ">" |head -n1)
    echo "Source Filename :" (exiftool -j "$argv[1]" |jq -r .[].FileName)
    echo "Source Filesize :" (exiftool -j "$argv[1]" |jq -r .[].FileSize)
    echo "Source MIME Type:" (exiftool -j "$argv[1]" |jq -r .[].MIMEType)
    echo "Source Encoding :" (exiftool -j "$argv[1]" |jq -r .[].MIMEEncoding)
    figlet -w 140 -f digital.flf "Emails" | lolcat
    echo "Unique Emails   :"
    rg -N -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" "$argv[1]" |sort -u
    figlet -w 140 -f digital.flf "Path" | lolcat
    echo "Path Trace      :"
    rg -N -A 4 "^Received: from " "$argv[1]"
    end
