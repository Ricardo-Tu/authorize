#!/bin/bash
#
set -o errexit

function enable_forward {
    echo setup_forward_port
    # execute once
    KVM_ADAPTER_NAME="br0"
    KVM_SUBNET="192.168.50.1/24"
    
    WAN_ADAPTER_NAME="enp6s0"
    # allow virtual adapter to accept packets from outside the host
    iptables -I FORWARD -i $WAN_ADAPTER_NAME -o $KVM_ADAPTER_NAME -d $KVM_SUBNET -j ACCEPT
    iptables -I FORWARD -i $KVM_ADAPTER_NAME -o $WAN_ADAPTER_NAME -s $KVM_SUBNET -j ACCEPT
    
    #WAN_ADAPTER_NAME="cni0"
    ## allow virtual adapter to accept packets from host k8s container
    ## forward change destination, but not change source interface
    #iptables -I FORWARD -i $WAN_ADAPTER_NAME -o $KVM_ADAPTER_NAME -d $KVM_SUBNET -j ACCEPT
    #iptables -I FORWARD -i $KVM_ADAPTER_NAME -o $WAN_ADAPTER_NAME -s $KVM_SUBNET -j ACCEPT
    ## iptables -I FORWARD -s 10.244.0.0/16 -d $KVM_SUBNET -j ACCEPT
    
    #WAN_ADAPTER_NAME="docker0"
    ## allow virtual adapter to accept packets from host docker container
    ## forward change destination, but not change source interface
    #iptables -I FORWARD -i $WAN_ADAPTER_NAME -o $KVM_ADAPTER_NAME -d $KVM_SUBNET -j ACCEPT
    #iptables -I FORWARD -i $KVM_ADAPTER_NAME -o $WAN_ADAPTER_NAME -s $KVM_SUBNET -j ACCEPT
}



function setup_forward_port {
    KVM_ADAPTER_HOST=$1
    WAN_PORT=$2
    KVM_PORT=$3
    
    echo setup_forward_port $KVM_ADAPTER_HOST
    
    adapter_hosts=("10.1.36.45")
    for WAN_ADAPTER_HOST in "${adapter_hosts[@]}"
    do
            echo "Forwarding wan_adapter_hosts: $WAN_ADAPTER_HOST"
            # forward ports from outer-host to guest
            iptables -t nat -I PREROUTING -d $WAN_ADAPTER_HOST -p tcp --dport $WAN_PORT -j  DNAT --to-destination $KVM_ADAPTER_HOST:$KVM_PORT
            # forward ports from inner-host to guest
            iptables -t nat -I OUTPUT -d $WAN_ADAPTER_HOST -p tcp --dport $WAN_PORT -j DNAT --to-destination $KVM_ADAPTER_HOST:$KVM_PORT
    done
}

function list_forward {
    KVM_ADAPTER_HOST=$1
    echo list_forward $KVM_ADAPTER_HOST
    echo "Processing chain: PREROUTING"
    iptables --line-numbers --list PREROUTING -t nat | awk -F: '$3=="'$KVM_ADAPTER_HOST'"''{print}'
    echo "Processing chain: OUTPUT"
    iptables --line-numbers --list OUTPUT -t nat | awk -F: '$3=="'$KVM_ADAPTER_HOST'"''{print}'
}

function list_forward_port {
    KVM_ADAPTER_HOST=$1
    KVM_PORT=$2
    echo list_forward_port $KVM_ADAPTER_HOST
    iptables --line-numbers --list PREROUTING -t nat | awk '$9=="to:'$KVM_ADAPTER_HOST':'$KVM_PORT'" {print}'
    iptables --line-numbers --list OUTPUT -t nat | awk '$9=="to:'$KVM_ADAPTER_HOST':'$KVM_PORT'" {print}'
    # iptables -t nat -nvL OUTPUT
}

function clear_forward_port {
    KVM_ADAPTER_HOST=$1
    KVM_PORT=$2
    echo clear_forward_port $KVM_ADAPTER_HOST
    
    iptables_chains=("PREROUTING" "OUTPUT")
    for chain in "${iptables_chains[@]}"
    do
            echo "Processing chain: $chain"
            for line_num in $(iptables --line-numbers --list $chain -t nat | awk '$9=="to:'$KVM_ADAPTER_HOST':'$KVM_PORT'" {print $1}')
            do
                    # You can't just delete lines here because the line numbers get reordered
                    # after deletion, which would mean after the first one you're deleting the
                    # wrong line. Instead put them in a reverse ordered list.
                    LINES="$line_num $LINES"
            done
        
            # Delete the lines, last to first.
            for line in $LINES
            do
                    # echo $lin  e
                    iptables -t nat -D $chain $line
            done
            unset LINES
    done
    
}

enable_forward


# setup iptables
# ubuntu desktop vm0
KVM_ADAPTER_HOST="192.168.50.251"
setup_forward_port $KVM_ADAPTER_HOST 22622 22 # ssh

list_forward $KVM_ADAPTER_HOST


#KVM_ADAPTER_HOST="192.168.122.79"
#clear_forward_port $KVM_ADAPTER_HOST 22 # ssh
