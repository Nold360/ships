#!/bin/ash
##############################################################################################################
# SHIPS - SHell Intrusion Prevention System
##############################################################################################################
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
##############################################################################################################
# Copyright (c) 2013, Gerrit 'Nold' Pannek
# All rights reserved.
# See LICENSE-File which should come with this Script.
##############################################################################################################
#
# Homepage: http://nold.in
# Mail: nold@freeboxes.net
#
##############################################################################################################


##############################################################################################################
# Get Configparameter $1 from file $2, or just all parameters from file $1
##############################################################################################################
get_config() {
        if [ $# -eq 2 ] ; then
                awk -v param=$1 '{ if($1 !~ /^\#.*$/ && $1 !~ /^$/) { sub(/\ \#.*$/,""); sub(/=/, " ") ; $1 = $1 ; if($1 == param) print } }' $2 | cut -f2- -d" " | head -1
        elif [ $# -eq 1 ] ; then
                awk '{ if($1 !~ /^\#.*$/ && $1 !~ /^$/) { sub(/\ \#.*$/,""); sub(/=/, " ") ; $1 = $1 ; print } }' $1
        fi
}

read_config () {
        failed=0

        test -f /etc/ships/ships.conf || (echo "ERROR: Can't open /etc/ships/ships.conf" && return 1)

        OLD_IFS=$IFS
        IFS=$'\n'

        #Get MAIN-Config
        for line in $(get_config /etc/ships/ships.conf); do
                eval $(echo $line | cut -f1 -d" ")=$(echo $line | cut -f2- -d" ")
        done

        #Get all Configs for jail
        local count=0
        #Find all available configs
        type=jail
        for file in $(find /etc/ships/${type}.d/ -name "*.conf" -type f) ; do
                #Skip disabled Jails
                if [ "$type" == "jail" ] ; then
                        #Skip if jail is disabled
                        [ "$(get_config enabled $file)" == "true" ] || continue
                fi

                #Give TYPE-Number a name
                eval ${type}_${count}=$(basename $file | cut -f1 -d.)

                #"Reverse" lookup possibility
                eval ${type}_$(basename $file | cut -f1 -d.)=${count}

                #Add all available Variables, love this way to do it :)
                for line in $(get_config $file); do
                        echo $line | grep -q enabled && continue

                        eval ${type}_${count}_$(echo $line | cut -f1 -d" ")=$(echo $line | cut -f2- -d" ")
                        eval ${type}_${count}_variables=$(eval echo "$"${type}_${count}_variables | cut -f3- -d_)+$(echo $line | cut -f1 -d" ")
                done

                [ ! -f "/etc/ships/action.d/$(eval echo "$"${type}_${count}_action).conf" ] && logger -t SHIPS -p daemon.err "ERROR: Action $(eval echo "$"${type}_${count}_action) dosn't exist" && return 1

                local count=$(($count + 1))
        done
        IFS=$OLD_IFS

        #Check if available Actions are OK
        for file in $(find /etc/ships/action.d/ -name "*.conf" -type f) ; do
                for action in start stop ban unban check; do
                        if [ -z "$(get_config $action $file)" ]; then
                                logger -t SHIPS -p daemon.err "ERROR: Action $file dosn't support \"$action\""
                                failed=1
                        fi
                done
        done
        return $failed
}

start_jail() {
        #set -x
        local jail_nr=$1
        local name=$(eval echo "$"jail_${jail_nr})
        local logpath=$(eval echo "$"jail_${jail_nr}_logpath)
        local filter=$(eval echo "$"jail_${jail_nr}_filter)
        local maxretry=$(eval echo "$"jail_${jail_nr}_maxretry)
        local port=$(eval echo "$"jail_${jail_nr}_port)
        local action=$(eval echo "$"jail_${jail_nr}_action)

        local regex=$(get_config failregex /etc/ships/filter.d/${filter}.conf)

        #Read out Action
        for var in start stop ban unban check; do
                value=$(get_config $var /etc/ships/action.d/${action}.conf)
                value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
                eval action${var}=\"$value\"
        done

        #Should we use logread or just tail a logfile?
        if [ "$logpath" == "LOGREAD" ] ; then
                local logaction="logread -f"
        else
                local logaction="tail -fn0 $logpath"
        fi

        #Check if action is started
        if ! eval $actioncheck ; then
                #START_ACTION
                eval $actionstart
        fi

        OLD_IFS=$IFS
        IFS=$'\n'
        eval $logaction | \
        while read line ; do
                IFS=$'\n'
                if echo "$line" | egrep -q $regex; then
                        IFS=$OLD_IFS
                        #Do we have a IP?
                        for part in $line; do
                                if echo $part | grep -q -o "\(^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?$"; then
                                        local source_ip=$(echo $part | grep -o "\(^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?$" | cut -f1 -d:)

                                        local skip=0
                                        #Should this IP be ignored
                                        #FIXME: We might want to exclude Subnets and hostnames will also fail
                                        for ip in $(get_config IGNORE_IP /etc/ships/ships.conf | tr "," " ") ; do
                                                if [ "$source_ip" == "$ip" ] ; then
                                                        local skip=1
                                                        break
                                                fi
                                        done
                                        [ $skip -eq 1 ] && echo ignore $source_ip && break

                                        #Got no entry? Add counter
                                        if ! grep -q "${name}:${source_ip}:" $FAILLOG ; then
                                                [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Adding $source_ip in jail $name"
                                                echo "${name}:${source_ip}:1:$(date +'%s')" >> $FAILLOG
                                        else
                                        #Got entry, Increment counter or Ban client
                                                local count=$(grep "${name}:${source_ip}:" $FAILLOG | cut -f3 -d:)
                                                if [ "$count" != "B" ] ; then
                                                        if [ $count -ge $maxretry ] ; then
                                                                #Ban client
                                                                [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Banning $source_ip in jail $name"
                                                                eval $(echo $actionban | sed "s/<ip>/${source_ip}/g")
                                                                sed -i "s/${name}:${source_ip}:.*$/${name}:${source_ip}:B:$(date +'%s')/g" $FAILLOG
                                                        else
                                                                local count=$(( $count + 1 ))
                                                                [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Updateing counter to $count for $source_ip in jail $name"
                                                                sed -i "s/${name}:${source_ip}:.*$/${name}:${source_ip}:${count}:$(date +'%s')/g" $FAILLOG
                                                        fi
                                                fi
                                        fi
                                        break
                                fi
                        done
                fi
        done
}

stop_jail() {
        #set -x
        jail_nr=$1
        pid=$(eval echo "$"jail_${jail_nr}_pid)
        action=$(eval echo "$"jail_${jail_nr}_action)
        name=$(eval echo "$"jail_${jail_nr})
        port=$(eval echo "$"jail_${jail_nr}_port)

        value=$(get_config stop /etc/ships/action.d/${action}.conf)
        value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
        eval actionstop=\"$value\"
        [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Stopping Jail $name"

        kill -9 $pid
        eval $actionstop
        return 0
}

#########################################################################################
# Unbanner : Daemon that deletes entryes from FAILLOG if BANTIME or RESET_AFTER expired
#            Also it will execute the unban action from the specific jail
#########################################################################################
unbanner() {
        RESET_AFTER=$(get_config RESET_AFTER /etc/ships/ships.conf)
        [ -z $RESET_AFTER ] && RESET_AFTER=6000
        while true; do
                for line in $(cat $FAILLOG); do
                        if echo $line | grep -q ":B:" ; then
                                banned_time=$(echo $line | cut -f4 -d:)
                                time_left=$(( $(date +'%s') - $banned_time  ))
                                if [ $time_left -ge $BANTIME ] ; then
                                        jailname=$(echo $line | cut -f1 -d:)
                                        source_ip=$(echo $line | cut -f2 -d:)
                                        jailnr=$(eval echo "$"jail_${jailname})
                                        action=$(eval echo "$"jail_${jailnr}_action)
                                        unban=$(get_config unban /etc/ships/action.d/${action}.conf)
                                        unban=$(echo $unban | sed "s/<name>/${jailname}/g" | sed "s/<ip>/${source_ip}/g")
                                        [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "UNbanning $source_ip in jail $jailname"
                                        eval $unban
                                        sed -i "/${jailname}:${source_ip}:B:.*$/d" $FAILLOG
                                fi
                        #Remove everyone who hasn't tried to connect for RESET_AFTER Seconds
                        elif [ $(( $(echo $line | cut -f4 -d:) + $RESET_AFTER )) -lt $(date +'%s') ] ; then
                                jailname=$(echo $line | cut -f1 -d:)
                                source_ip=$(echo $line | cut -f2 -d:)
                                [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Cleaning entry for $source_ip in jail $jailname"
                                sed -i "/${jailname}:${source_ip}:.*:$(echo $line | cut -f4 -d:)$/d" $FAILLOG
                        fi
                done
                sleep 1
        done
}

stop_all_jails() {
        local count=0
        while [ ! -z "$(eval echo "$"jail_${count})" ] ; do
                stop_jail ${count}
                local count=$(( $count + 1 ))
        done
}

read_config || exit 1

local count=0
while [ ! -z "$(eval echo "$"jail_${count})" ] ; do
        start_jail $count &
        eval jail_${count}_pid=$!
        local count=$(( $count + 1 ))
done
unbanner &
unbanner_pid=$!

trap "stop_all_jails &> /dev/null; logger -t SHIPS -p daemon.notice \"SHIPS-Daemon is going down...\"; kill -9 $unbanner_pid ; exit 0" SIGINT SIGTERM SIGKILL

logger -t SHIPS -p daemon.notice "SHIPS-Daemon started and running..."
while true; do
        sleep 1
done


exit 0
