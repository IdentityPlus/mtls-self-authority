#!/bin/bash

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if !(crontab -l | grep -q update-mtls-id.sh) ; then
    echo "installing agent mTLS ID update cron job for 2AM every day"
    (crontab -l ; echo "0 4 * * * $DIR/update-mtls-id.sh \"$1\" \"$2\"") | sort - | uniq - | crontab -
fi

echo -n "updating agent mTLS ID on device... "
RESULT_A=$( $DIR/selfauthority -f "$1" -d "$2" update )
echo $RESULT_A

if [[ $RESULT_S == "renewed" ]]
    then
	    echo "reloading mtls-persona ... "
        kill $(pidof mtls-persona)
	    echo "done."
    else
	    echo "nothing to do ..."
    fi

