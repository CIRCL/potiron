#!/bin/bash
for file in $1*.csv ; do
	name=$( echo ${file} | rev | cut -f1 -d/ | rev | cut -f1 -d.)
	echo ${name}
	cat "template.html" | sed -e "s/##NAME##/${name}/g" >$1/${name}.html
done
exit 0
