function test() {
    if [ $1 == 0 ]; then
        echo "Pass  $2"
    else
        echo "Fail  $2"
    fi
}

a=$(diff arpspoofing_output.txt <(python scanner.py arpspoofing.pcap) | wc -l)
test $a 'arpspoofing'

b=$(diff portscan_output.txt <(python scanner.py portscan.pcap) | wc -l)
test $b 'portscan'

c=$(diff synflood_output.txt <(python scanner.py synflood.pcap) | wc -l)
test $c 'synflood'