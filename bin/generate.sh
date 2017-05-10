#!/bin/bash
for file in $1*.csv ; do
	name=$( echo ${file} | rev | cut -f1 -d/ | rev | cut -f1 -d.)
	if [ -z "$2" ]
	then
		logo="$(dirname "$(pwd)")/doc/circl.png"
	else
		logo=$2
	fi
	cat "template.html" | sed -e "s/##NAME##/${name}/g" | sed -e "s_##LOGO##_${logo}_g" >$1/${name}.html
done
exit 0
