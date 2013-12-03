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
# See COPYRIGHT-File which should come with this Script.
##############################################################################################################
#
# Homepage: http://nold.in
# Mail: nold@freeboxes.net
#
##############################################################################################################

read_config () {
	OLD_IFS=$IFS
	IFS=$'\n'
	#Get MAIN-Config
	for line in $(grep -v "^\#" /etc/ships/ships.conf); do
		eval $(echo $line | cut -f1 -d"=")=$(echo $line | cut -f2 -d"=")
	done
	
	#Get all Configs for jail
	for type in jail; do
		count=0
		#Find all available configs
		for file in $(find /etc/ships/${type}.d/ -name "*.conf" -type f) ; do
			#Skip disabled Jails
			if [ "$type" == "jail" ] ; then
				egrep -v "^\#" $file | grep -qi "enabled=true" || continue
			fi
			
			#Give TYPE-Number a name
			eval ${type}_${count}=$(basename $file | cut -f1 -d.)
			#"Reverse" lookup possibility
			eval ${type}_$(basename $file | cut -f1 -d.)=${count}
	
			#Add all available Variables, love this way to do it :)
			for line in $(egrep -v "^\#|enabled" $file); do
				eval ${type}_${count}_$(echo $line | cut -f1 -d"=")=$(echo $line | cut -f2- -d"=")
				eval ${type}_${count}_variables=$(eval echo "$"${type}_${count}_variables | cut -f3- -d_)+$(echo $line | cut -f1 -d"=")
			done
			count=$(($count + 1))
		done
		IFS=$OLD_IFS
	done

	#Check if available Actions are OK
	failed=0
	for file in $(find /etc/ships/action.d/ -name "*.conf" -type f) ; do
		for action in start stop ban unban check; do
			if ! egrep -v "^\#" $file | grep -q $action; then
				echo "ERROR: Action $file dosn't support \"$action\"" 
				failed=1
			fi
		done
	done
	return $failed
}

start_jail() {
	#set -x
	jail_nr=$1
	name=$(eval echo "$"jail_${jail_nr})
	logpath=$(eval echo "$"jail_${jail_nr}_logpath)
	filter=$(eval echo "$"jail_${jail_nr}_filter)
	maxretry=$(eval echo "$"jail_${jail_nr}_maxretry)
	port=$(eval echo "$"jail_${jail_nr}_port)
	action=$(eval echo "$"jail_${jail_nr}_action)

	regex=$(grep failregex /etc/ships/filter.d/${filter}.conf | cut -f2- -d"=")
	
	#set -x
	#Read out Action 
	for var in start stop ban unban check; do
		value=$(egrep "^$var\=" /etc/ships/action.d/${action}.conf | cut -f2- -d"=")
		value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
		eval action${var}=\"$value\"
	done
	                                                                                                                                 
	if [ "$logpath" == "LOGREAD" ] ; then
		logaction="logread -f"
	else
		logaction="tail -fn0 $logpath"
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
			for part in $line; do
				if echo $part | grep -q -o "\(^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?$"; then
					source_ip=$(echo $part | grep -o "\(^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?$" | cut -f1 -d:)
					if ! grep -q "${name}:${source_ip}:" $FAILLOG ; then
						echo "${name}:${source_ip}:1" >> $FAILLOG
						echo "Adding counter"
					else
						count=$(grep "${name}:${source_ip}:" $FAILLOG | cut -f3 -d:)
						if [ "$count" != "B" ] ; then
							if [ $count -ge $maxretry ] ; then
								#Ban client
								echo "Ban: $source_ip"
								eval $(echo $actionban | sed "s/<ip>/${source_ip}/g")
								sed -i "s/${name}:${source_ip}:.*$/${name}:${source_ip}:B:$(date +'%s')/g" $FAILLOG
							else
								count=$(( $count + 1 ))
								echo "New count: $count"
								sed -i "s/${name}:${source_ip}:.*$/${name}:${source_ip}:${count}/g" $FAILLOG
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

	value=$(egrep "^stop\=" /etc/ships/action.d/${action}.conf | cut -f2- -d"=")
	value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
	eval actionstop=\"$value\"
                        
        kill -9 $pid                        	
	eval $actionstop	
	return 0
}


unbanner() {
	while true; do
		for line in $(grep ":B:" $FAILLOG); do
			banned_time=$(echo $line | cut -f4 -d:)
			time_left=$(( $(date +'%s') - $banned_time  ))
			if [ $time_left -ge $BANTIME ] ; then
				echo "unban client"
				jailname=$(echo $line | cut -f1 -d:)
				source_ip=$(echo $line | cut -f2 -d:)
				jailnr=$(eval echo "$"jail_${jailname})
				action=$(eval echo "$"jail_${jailnr}_action)
				unban=$(grep "^unban=" /etc/ships/action.d/${action}.conf | cut -f2 -d"=")
				unban=$(echo $unban | sed "s/<name>/${jailname}/g" | sed "s/<ip>/${source_ip}/g")
				eval $unban
				sed -i "/${jailname}:${source_ip}:B:.*$/d" $FAILLOG
			fi
		done
		sleep 1
	done
}

stop_all_jails() {
	count=0
	while [ ! -z "$(eval echo "$"jail_${count})" ] ; do
		stop_jail ${count}
		count=$(( $count + 1 ))
	done
}

read_config || exit 1

test -d $(dirname $FAILLOG) || mkdir -p $(dirname $FAILLOG)
echo "" > $FAILLOG || exit 1

count=0
while [ ! -z "$(eval echo "$"jail_${count})" ] ; do
	start_jail $count &
	eval jail_${count}_pid=$!
	count=$(( $count + 1 ))
done
unbanner &

trap "stop_all_jails &> /dev/null ; exit 0" SIGINT SIGTERM SIGKILL

while true; do
	sleep 1
done


exit 0
