#!/bin/ash
. /usr/share/ships/ships_functions.sh

##############################################################################################################
# stop_all_jails
# Params: -
# Return: -
# Helper function which will kill all JAILs
##############################################################################################################
stop_all_jails() {
	set -x
        local count=0
	killall ships_jail.sh
#        while [ ! -z "$(eval echo "$"jail_${count}_pid)" ] ; do
#                kill -9 $(eval echo "$"jail_${count}_pid)
#                local count=$(( $count + 1 ))
#        done
}

##############################################################################################################
# check_config
# Params:
# Return: 0 or 1 if config test failes
# This function reads ships.conf and action configs, jail-configs will be checked by jail itself
# Actions will also be checkt for compatiblitity
##############################################################################################################
check_config () {
	failed=0

	test -f /etc/ships/ships.conf || (echo "ERROR: Can't open /etc/ships/ships.conf" && return 1)

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


##############################################################################################################
# MAIN
##############################################################################################################
check_config || exit 1
set -x
#Start every available jail
local count=0
for jail in $(ls -1 /etc/ships/jail.d/*.conf); do
	jail_file=$(basename $jail)
	jail_name=${jail_file%.*}
        /usr/share/ships/ships_jail.sh $jail_name &> /dev/null &  
        eval jail_${count}_pid=$!
        eval jail_${count}_name=$jail_name
        local count=$(( $count + 1 ))
done

/usr/share/ships/ships_unbanner.sh &> /dev/null &
unbanner_pid=$!

trap "stop_all_jails ; kill -9 $unbanner_pid;  logger -t SHIPS -p daemon.notice \"SHIPS-Daemon is going down...\"; exit 0" SIGINT SIGTERM SIGKILL SIGQUIT

#eval echo "$"unbanner_pid >> /tmp/pid_unbanner

logger -t SHIPS -p daemon.notice "SHIPS-Daemon started and running..."
while true; do
        sleep 1
done

exit 0

