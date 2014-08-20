#!/bin/ash
. /usr/share/ships/ships_functions.sh

##############################################################################################################
# stop_jail
# Params: JAIL_NAME PID_OF_JAIL
# Return: 0
# Stops a single JAIL defined by JAIL_NUMBER. It will execute the STOP-Command of the JAILs ACTION
##############################################################################################################
stop_jail() {
	#set -x
        jail_name=$1
        pid=$2

        #Test if process exists, otherwise exit
        kill -0 $pid 2>/dev/null || exit 0

        read_jail_config ${jail_name}

        value=$(get_config stop /etc/ships/action.d/${action}.conf)
        value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
        eval actionstop=\"$value\"
        [ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Stopping jail: $name [$pid]"

        #Execute Stop-Action
        eval $actionstop

        #Kill jail
        kill -9 $pid

        return 0
}


##############################################################################################################
# start_jail
# Params: jail_number
# Return: -
# Starts jail and runs forever. It's reading the config file specified in JAIL and
# checks for defines regex. Also it will execute the ACTION of the JAIL.
##############################################################################################################
start_jail() {
	#set -x
        local name=${1}

	read_jail_config ${name} || exit 1

	local regex=$(get_config failregex /etc/ships/filter.d/${filter}.conf)

	#trap calls itself it you try to kill this jail
	trap "stop_jail ${1} $$ ; exit 0" SIGINT SIGTERM SIGKILL SIGQUIT

	#Read out Action
	for var in start stop ban unban check; do
		value=$(get_config $var /etc/ships/action.d/${action}.conf)
		value=$(echo $value | sed "s/<name>/${name}/g" | sed "s/<port>/${port}/g" )
		eval action${var}=\"$value\"
	done

	#Should we use logread or just tail a logfile?
	if [ "$logpath" == "LOGREAD" ] ; then
		local logaction="logread -fp /var/run/ships_jail_${name}_logread.pid"
	else
		local logaction="tail -fn0 $logpath"
	fi

	#Check if action is started
	if ! eval $actioncheck ; then
		#START_ACTION
		eval $actionstart
	fi

	[ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Starting jail: $name [$$]"

	OLD_IFS=$IFS
	IFS=$'\n'
	eval $logaction | \
	while read line ; do
		IFS=$'\n'
		if echo "$line" | egrep -q $regex; then
			IFS=$OLD_IFS
			#Do we have a IP?
			for part in $line; do
				if echo $part | grep -q -o "\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?"; then
					local source_ip=$(echo $part | grep -o "\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\(:[0-9]\{0,5\}\)\?" | cut -f1 -d:)

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
						[ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Adding $source_ip to jail $name"
						echo "${name}:${source_ip}:1:$(date +'%s')" >> $FAILLOG
					else
					#Got entry, Increment counter or Ban client
						local count=$(grep "${name}:${source_ip}:" $FAILLOG | cut -f3 -d:)
						if [ "$count" != "B" ] ; then
							if [ $count -ge $maxretry ] ; then
								#Ban client
								[ "$DEBUG" == "1" ] && logger -t SHIPS -p daemon.notice "Banning $source_ip to jail $name"
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

read_main_config || exit 1
start_jail $@
