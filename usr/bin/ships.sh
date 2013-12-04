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
	failed=0

	test -f /etc/ships/ships.conf || (echo "ERROR: Can't open /etc/ships/ships.conf" && return 1)
	
	OLD_IFS=$IFS
	IFS=$'\n'
	
	#Get MAIN-Config
	for line in $(grep -v "^\#" /etc/ships/ships.conf); do
		eval $(echo $line | cut -f1 -d"=")=$(echo $line | cut -f2 -d"=")
	done
	
	#Get all Configs for jail
	local count=0
	#Find all available configs
	type=jail
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
		
		[ ! -f "/etc/ships/action.d/$(eval echo "$"${type}_${count}_action).conf" ] && echo "ERROR: Action $(eval echo "$"${type}_${count}_action) dosn't exist" && return 1
		
		local count=$(($count + 1))
	done
	IFS=$OLD_IFS

	#Check if available Actions are OK
	for file in $(find /etc/ships/action.d/ -name "*.conf" -type f) ; do
		for action in start stop ban unban check; do
			if ! egrep -v "^\#" $file | grep -q $action | head -1; then
				echo "ERROR: Action $file dosn't support \"$action\"" 
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

	local regex=$(grep failregex /etc/ships/filter.d/${filter}.conf | cut -f2- -d"=")
	
	#set -x
	#Read out Action 
	for var in start stop ban unban check; do
		value=$(egrep "^$var\=" /etc/ships/action.d/${action}.conf | cut -f2- -d"=")
		value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
		eval local action${var}=\"$value\"
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
					for ip in $(grep IGNORE_IP /etc/ships/ships.conf | cut -f2 -d= | tr "," " ") ; do
						if [ "$source_ip" == "$ip" ] ; then
							local skip=1
							break
						fi
					done
					[ $skip -eq 1 ] && echo ignore $source_ip && break
					
					#Got no entry? Add counter
					if ! grep -q "${name}:${source_ip}:" $FAILLOG ; then
						echo "${name}:${source_ip}:1:$(date +'%s')" >> $FAILLOG
						echo "Adding counter"
					else
					#Got entry, Increment counter or Ban client
						local count=$(grep "${name}:${source_ip}:" $FAILLOG | cut -f3 -d:)
						if [ "$count" != "B" ] ; then
							if [ $count -ge $maxretry ] ; then
								#Ban client
								echo "Ban: $source_ip"
								eval $(echo $actionban | sed "s/<ip>/${source_ip}/g")
								sed -i "s/${name}:${source_ip}:.*$/${name}:${source_ip}:B:$(date +'%s')/g" $FAILLOG
							else
								local count=$(( $count + 1 ))
								echo "New count: $count"
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

	value=$(egrep "^stop\=" /etc/ships/action.d/${action}.conf | cut -f2- -d"=")
	value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
	eval actionstop=\"$value\"
                        
        kill -9 $pid                        	
	eval $actionstop	
	return 0
}

#########################################################################################
# Unbanner : Daemon that deletes entryes from FAILLOG if BANTIME or RESET_AFTER expired
#            Also it will execute the unban action from the specific jail
#########################################################################################
unbanner() {
	RESET_AFTER=$(grep "^RESET_AFTER=" /etc/ships/ships.conf | head -1 | cut -f2 -d=)
	[ -z $RESET_AFTER ] && RESET_AFTER=6000
	while true; do
		for line in $(cat $FAILLOG); do
			if echo $line | grep -q ":B:" ; then
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
			#Remove everyone who hasn't tried to connect for RESET_AFTER Seconds
			elif [ $(( $(echo $line | cut -f4 -d:) + $RESET_AFTER )) -lt $(date +'%s') ] ; then
				echo "Cleaning up!"
				jailname=$(echo $line | cut -f1 -d:)
				source_ip=$(echo $line | cut -f2 -d:)
				sed -i "/${jailname}:${source_ip}:.*:$(echo $line | cut -f4 -d:)$/d" $FAILLOG	
				echo sed -i "/${jailname}:${source_ip}:.*:$(echo $line | cut -f4 -d:)$/d" $FAILLOG	
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

trap "stop_all_jails &> /dev/null; kill -9 $unbanner_pid ; exit 0" SIGINT SIGTERM SIGKILL

while true; do
	sleep 1
done
exit 0

