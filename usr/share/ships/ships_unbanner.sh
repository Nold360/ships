#!/bin/ash
. /usr/share/ships/ships_functions.sh

#########################################################################################
# unbanner
# Params: -
# Return: -
# Daemon that deletes entryes from FAILLOG if BANTIME or RESET_AFTER expired
# Also it will execute the unban action from the specific jail
#########################################################################################
unbanner() {
set -x
	RESET_AFTER=$(get_config RESET_AFTER /etc/ships/ships.conf)
	[ -z $RESET_AFTER ] && RESET_AFTER=6000
	trap "exit 0" SIGINT SIGTERM SIGKILL SIGQUIT

	while true; do
		for line in $(cat $FAILLOG); do
			# Is someone banned?
			if echo $line | grep -q ":B:" ; then
				# Has he been banded long enoth?
				banned_time=$(echo $line | cut -f4 -d:)
				time_left=$(( $(date +'%s') - $banned_time  ))
				if [ $time_left -ge $BANTIME ] ; then
					jailname=$(echo $line | cut -f1 -d:)
					source_ip=$(echo $line | cut -f2 -d:)
					jailnr=$(eval echo "$"jail_${jailname})
					action=$(eval echo "$"jail_${jailnr}_action)
					unban=$(get_config unban /etc/ships/action.d/${action}.conf)
					unban=$(echo $unban | sed "s/<name>/${jailname}/g" | sed "s/<ip>/${source_ip}/g")
					[ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Unbanning $source_ip from jail $jailname"
					eval $unban
					sed -i "/${jailname}:${source_ip}:B:.*$/d" $FAILLOG
				fi
			#Remove everyone who hasn't tried to connect for RESET_AFTER Seconds
			elif [ $(( $(echo $line | cut -f4 -d:) + $RESET_AFTER )) -lt $(date +'%s') ] ; then
				jailname=$(echo $line | cut -f1 -d:)
				source_ip=$(echo $line | cut -f2 -d:)
				[ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Cleaning entry for $source_ip from jail $jailname"
				sed -i "/${jailname}:${source_ip}:.*:$(echo $line | cut -f4 -d:)$/d" $FAILLOG
			fi
		done
		sleep 1
	done
}

read_main_config
unbanner
