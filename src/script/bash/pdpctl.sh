#! /bin/bash

# This script starts and stop the PDP daemon.

# PDP home directory
HOME="$(cd "${0%/*}/.." && pwd)"

# Source our environment setup script
. $HOME/bin/env.sh

function start {        
    # Add the PDP home directory property
    JVMOPTS="-Dorg.glite.authz.pdp.home=$HOME $JVMOPTS"
    
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemon' "$1" &
}

function stop {
    ECODE=`curl --connect-timeout 3 --max-time 5 -s --show-error http://127.0.0.1:"$1"/shutdown`
    if [ $ECODE -ne 0 ] ; then
       echo "Shutdown failed.  curl returned error code of $ECODE"
    fi
}

function print_help {
   echo "PDP start/stop script"
   echo ""
   echo "Usage:"
   echo "  pdpctl.sh start <config_file>   - to start the service"
   echo "  pdpctl.sh stop <shutdown_port>  - to stop the service" 
   echo ""
}

if [ $# -lt 2 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'start') start $2;;
  'stop') stop $2;;
  *) print_help ;;
esac