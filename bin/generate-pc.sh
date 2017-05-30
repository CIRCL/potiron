#!/bin/bash
for file in $1parallel-coordinate*.csv ; do
	name=$( echo ${file} | rev | cut -f1 -d/ | rev | cut -f1 -d.)
	if [ -z "$2" ]
	then
		logo="$(dirname "$(pwd)")/doc/circl.png"
	else
		logo=$2
	fi
	echo ${name}
	cat "template-pc.html" | sed -e "s/##NAME##/${name}/g" >$1/${name}.html
done
exit 0
