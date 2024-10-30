#!/bin/bash

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if !(crontab -l | grep -q update-service-id.sh) ; then
    echo "installing service update cron job for 4AM every daily"    
    (crontab -l ; echo "0 4 * * * $DIR/update-service.sh \"$1\" \"$2\"") | sort - | uniq - | crontab -
fi

echo -n "updating service identity ... "
RESULT_S=$( $DIR/selfauthority -f "$1" -d "$2" update-service )
echo $RESULT_S

if [[ $RESULT_S == "renewed" ]]
    then
	    echo "reloading openresty nginx service and mtls-persona ... "
        kill $(pidof mtls-persona)
        service openresty reload
	    echo "done."
    else
	    echo "nothing to do ..."
    fi
