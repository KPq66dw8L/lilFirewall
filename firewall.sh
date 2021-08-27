#!/bin/bash

# ./firewall.sh {action} {blockformat} {target}
# {action} -> block or unblock
# {blockformat} -> ip adress, iprange, country
# {target} -> 192.168.x.x, 192.168.x.x/24, DE/FR

WORKPLACE="/root/tmp"
ACTION="$1" #first argument
BLOCKFORMAT="$2" #second argument
TARGET="$3" #third argument 

# [[ X ]] is a single construct that makes X be parsed magically. <, &&, || and 
# () are treated specially, and word splitting rules are different. etc

# ! = True if expression is false. False if expression is true.

# -e = True if pathname resolves to an existing directory entry. 
# False if pathname cannot be resolved.

# -d = True if pathname resolves to an existing directory entry for a directory. 
# False if pathname cannot be resolved, or if pathname resolves to an existing 
# directory entry for a file that is not a directory.

# wget -q –> Évite l'affichage des messages du wget.
# wget -O -> enregistre l'output ds un fichier 



function check_workplace() {
    WORKPLACE="$1"

    if [[ ! -e "$WORKPLACE" ]] 
    then 
        echo "$WORKPLACE doesn't exist, creating..."
        mkdir "$WORKPLACE"
    else
        if [[ ! -d "$WORKPLACE" ]] 
        then  
            echo "Alert: $WORKPLACE is a file, exiting..."
            exit 1
        else    
            echo "$WORKPLACE is a directory, processing..."
        fi
    fi
}

function get_country() {
    WORKPLACE="$1"
    COUNTRY="$2"
    BASE_URL="http://www.ipdeny.com/ipblocks/data/aggregated"

    wget -q $BASE_URL/$COUNTRY-aggregated.zone -O $WORKPLACE/$COUNTRY.zone
}

function blockip() {
    IP="$1"
    # insérer en haut de la table INPUT (entrées) l'ip et refuser les packets de cet IP, verbosité probablement
    iptables -I INPUT -s "$IP" -j DROP -v 
}

function unblockip() {
    IP="$1"
    iptables -D INPUT -s "$IP" -j DROP -v 
}

function core() {
    ACTION="$1"
    BLOCKFORMAT="$2"
    TARGET="$3"
    WORKPLACE="$4"

    if [[ "$BLOCKFORMAT" = "country" ]]
    then 
        get_country "$WORKPLACE" "$TARGET"
        HOWMANYLINES=$(cat "$WORKPLACE/$TARGET.zone" | wc -l)

        if [[ "$ACTION" = "block" ]]
        then 
            SECONDS="0"
            echo "Processing blacklist $HOWMANYLINES for $TARGET country... please wait..."
            for LINE in $(cat "$WORKPLACE/$TARGET.zone")
            do
                blockip $LINE > /dev/null
            done 
            echo "Done! Country $TARGET ($HOWMANYLINES) processed in $SECONDS seconds."
        elif [[ "$ACTION" = "unblock" ]]
        then 
            SECONDS="0"
            echo "Processing unblacklist $HOWMANYLINES for $TARGET country... please wait..."
            for LINE in $(cat "$WORKPLACE/$TARGET.zone")
            do
                unblockip $LINE > /dev/null
            done 
            echo "Done! Country $TARGET ($HOWMANYLINES) processed in $SECONDS seconds."    
        else 
            echo "$ACTION invalid, exiting..."
            exit 1 
            fi
    elif [[ "$BLOCKFORMAT" = "ip" ]]
    then    
        if [[ "$TARGET" =~ (([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$ ]]
        then
            echo "$IP adress $TARGET is valid"

            if [[ "$TARGET" != "0.0.0.0" ]]
            then 
                if [[ "$ACTION" = "block" ]]
                then
                    echo "Processing blacklist $TARGET ... please wait..."
                    blockip "$TARGET"
                    echo "Done! $TARGET blocked"
                    
                elif [[ "$ACTION" = "unblock" ]]
                then
                    echo "Processing unblacklist $TARGET ... please wait..."
                    unblockip "$TARGET"
                    echo "Done! $TARGET unblocked"
                else 
                
                    echo "$ACTION invalid, process cancelled..."
                    exit 1
                fi
        
            else
                echo "You can't block the whole internet"
            fi
        elif [[ "$TARGET" =~ (([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\/([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$ ]]
        then
            echo "CIDR range $TARGET is valid"

            if [[ "$TARGET" != "0.0.0.0" ]]
            then
                if [[ "$ACTION" = "block" ]]
                then
                    echo "Processing blacklist $TARGET...please wait..."
                    blockip "$TARGET"
                    echo "Done! $TARGET blocked"

                elif [[ "$ACTION" = "unblock" ]]
                then
                    echo "Processing unblacklist $TARGET...please wait..."
                    unblockip "$TARGET"
                    echo "Done! $TARGET unblocked"
                else
                    echo "$ACTION invalid, process cancelled..."
                    exit 1
                fi
            else
                echo "You can't do this."
            fi
        else 
            echo "ERROR: $TARGET is an invalid IP adress or CIDR format"
            exit 1
        fi
    else
        echo "Block format: $BLOCKFORMAT invalid, exiting"
        exit 1
        fi
}

function action() {
    ACTION="$1"
    BLOCKFORMAT="$2"
    TARGET="$3"
    WORKPLACE="$4"

    check_workplace "$WORKPLACE"

    if [[ "$ACTION" = "help" ]]
    then
        echo "./firewall.sh {action} {blockformat} {target}"
        echo "{action} -> help, block or unblock"
        echo "{blockformat} -> ip or country"
        echo "{target} -> (192.168.x.x), (192.168.x.x/24) or countrycode (ex: fr)"
    
    elif [[ "$ACTION" = "block" ]]
    then   
        core $ACTION $BLOCKFORMAT $TARGET $WORKPLACE
    elif [[ "$ACTION" = "unblock" ]]
    then
        core $ACTION $BLOCKFORMAT $TARGET $WORKPLACE
    else
        echo "Invalid action, please retry..."
        exit 1
    fi
}

action $ACTION $BLOCKFORMAT $TARGET $WORKPLACE