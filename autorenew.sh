#!/bin/bash

if !(crontab -l | grep -q autorenew.sh) ; then
    DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
    echo "installing agent mTLS ID update cron job for 2AM every day"
    (crontab -l ; echo "0 4 * * * $DIR/autorenew.sh \"$1\" \"$2\"") | sort - | uniq - | crontab -
fi

echo -n "updating agent mTLS ID... "
RESULT_A=$( selfauthority update )
echo $RESULT_A

if [[ $RESULT_S == "renewed" ]]
    then
	    echo "mTLS ID has been renewed ... "
        # kill $(pidof mtls-persona)
	    # echo "done."
    else
	    echo "nothing to do ..."
    fi

