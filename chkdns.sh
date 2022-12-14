#!/usr/bin/env bash

if [ $# -ne 1 ]; then
    echo "This script compares the A record and PTR record of a host."
    echo "Usage 1: ./chkdns.sh lin2dev242"
    echo "Usage 2: ./chkdns.sh 10.74.206.3"
    echo "Usage 3: ./chkdns.sh hostlist.txt"
    exit 1
fi

get_ptr() {
    ARECORD_HOSTNAME=$(echo "$DNS_RETURN" | awk '{print $1}')
    ARECORD_IPADDR=$(echo "$DNS_RETURN" | awk '{print $4}')
    PTR=$(host "$ARECORD_IPADDR")

    if [[ $? -ne 0 ]]; then
        echo "$PTR"
    else
        PTR_RECORD_COUNT=$(echo "$PTR" | wc -l)
        if [[ $PTR_RECORD_COUNT -gt 1 ]]; then
            echo "Multiple PTR records returned."
            echo "$PTR"
        else
            echo "$PTR"
            PTR_HOSTNAME=$(echo "$PTR" | awk '{print $5}')
            PTR_HOSTNAME_PERIOD_STRIPPED=${PTR_HOSTNAME%?}
            if [[ "${ARECORD_HOSTNAME,,}" != "${PTR_HOSTNAME_PERIOD_STRIPPED,,}" ]]; then
                echo "Hostname in A record and PTR record do not match."
                echo "A:   $ARECORD_HOSTNAME"
                echo "PTR: $PTR_HOSTNAME"
            else
                echo "Records match."
            fi
        fi
    fi
}

get_arecord() {
    PTR_HOSTNAME=$(echo "$DNS_RETURN" | awk '{print $5}')
    ARECORD=$(host "$PTR_HOSTNAME")

    if [[ $? -ne 0 ]]; then
        echo "$ARECORD"
    else
        ARECORD_COUNT=$(echo "$ARECORD" | wc -l)
        if [[ $ARECORD_COUNT -gt 1 ]]; then
            echo "Multiple A records returned."
            echo "$ARECORD"
        else
            echo "$ARECORD"
            ARECORD_IPADDR=$(echo "$ARECORD" | awk '{print $4}')
            if [[ "$IPADDR" != "$ARECORD_IPADDR" ]]; then
                echo "IP address in PTR and A record do not match."
                echo "PTR:  $IPADDR"
                echo "A:    $ARECORD_IPADDR"
            else
                echo "Records match."
            fi
        fi
    fi
}

check_dns_records() {
    DNS_RETURN=$(host "$1")

    if [[ $? -ne 0 ]]; then
        echo "$DNS_RETURN"
    else
        RECORD_COUNT=$(echo "$DNS_RETURN" | egrep -c 'address|pointer')
        if [[ $RECORD_COUNT -gt 1 ]]; then
            echo "Multiple records returned."
            echo "$DNS_RETURN"
        else
            RECORD_TYPE=$(echo "$DNS_RETURN" | egrep -wo 'address|pointer')
            echo "$DNS_RETURN"
            if [[ "$RECORD_TYPE" == "address" ]]; then
                get_ptr $DNS_RETURN
            elif [[ "$RECORD_TYPE" == "pointer" ]]; then
                IPADDR=$1
                get_arecord $DNS_RETURN
            fi
        fi
    fi
}

if [ ! -f "$1" ]; then
    check_dns_records $1
else
    HOSTS=$(cat $1)
    for HOST in $HOSTS; do
        check_dns_records $HOST
        echo
    done
fi