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
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemon' $HOME/conf/pdp.ini &
}

function stop {
    curl --connect-timeout 3 --max-time 5 -s --show-error http://127.0.0.1:8153/shutdown
    ECODE=$?
    if [ "$ECODE" != 0 ] ; then
       echo "Shutdown failed.  curl returned error code of" $ECODE
    fi
}

function print_help {
   echo "PDP start/stop script"
   echo ""
   echo "Usage:"
   echo "  pdpctl.sh start   - to start the service"
   echo "  pdpctl.sh stop    - to stop the service" 
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'start') start;;
  'stop') stop;;
  *) print_help ;;
esac