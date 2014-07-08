#!/bin/ash
##############################################################################################################
# get_config
# Params: [CONFIG_PARAMTER] FILE_PATH
# Return: 0 or 1 if awk fails
# Get Configparameter CONFIG_PARAMETER from FILE_PATH, or just all parameters from file FILE_PATH
##############################################################################################################
get_config() {
	if [ $# -eq 2 ] ; then
		awk -v param=$1 '{ if($1 !~ /^\#.*$/ && $1 !~ /^$/) \
		{ sub(/\ \#.*$/,""); sub(/=/, " ") ; $1 = $1 ; if($1 == param) print } }' $2 | cut -f2- -d" " | head -1
	elif [ $# -eq 1 ] ; then
		awk '{ if($1 !~ /^\#.*$/ && $1 !~ /^$/) { sub(/\ \#.*$/,""); sub(/=/, " ") ; $1 = $1 ; print } }' $1
	fi
}


read_main_config () {
	IFS=$'\n'

	test -f /etc/ships/ships.conf || (echo "ERROR: Can't open /etc/ships/ships.conf" && return 1)

	#Get MAIN-Config
	for line in $(get_config /etc/ships/ships.conf); do
		eval $(echo $line | cut -f1 -d" ")=$(echo $line | cut -f2- -d" ")
	done
}


##############################################################################################################
# read_jail_config
# Params: jail-name
# Return: 0 or 1 if something failes
# This function reads ships.conf, jail and action configs
# Actions will also be checkt for compatiblitity
##############################################################################################################
read_jail_config () {
	name=${1}
	failed=0
	
	IFS=$'\n'
	#Get all Configs for jail
	type="jail"
	file="/etc/ships/${type}.d/${name}.conf"
	[ ! -e $file ] && logger -t SHIPS -p daemon.err "ERROR: ${file} dosn't exist" && return 1
	#Add all available Variables, love this way to do it :)
	for line in $(get_config $file); do
		echo $line | grep -q enabled && continue

		eval $(echo $line | cut -f1 -d" ")=$(echo $line | cut -f2- -d" ")
		eval variables=$(eval echo "$"${type}_${count}_variables | cut -f3- -d_)+$(echo $line | cut -f1 -d" ")
	done

	[ ! -f "/etc/ships/action.d/$(eval echo "$"action).conf" ] && \
		logger -t SHIPS -p daemon.err "ERROR: Action $(eval echo "$"action) dosn't exist" && \
		return 1

	return 0
}

