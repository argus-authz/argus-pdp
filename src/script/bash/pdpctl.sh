#! /bin/bash

# This script starts and stop the PDP daemon.

HOME="$(cd "${0%/*}/.." && pwd)"
CONF="$HOME/conf/pdp.ini"

# Source our environment setup script
. $HOME/bin/env.sh

function status {
    SHOST=`grep hostname $CONF | sed 's/ //g' | awk 'BEGIN {FS="="}{print $2}'`
    SPORT=`grep port $CONF | sed 's/ //g' | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z "$SPORT" ]; then
      SPORT=8152
    fi
    
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemonAdminCLI' "status" $SHOST $SPORT
}

function start {        
    # Add the PDP home directory property
    JVMOPTS="-Dorg.glite.authz.pdp.home=$HOME $JVMOPTS"
    
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemon' $CONF &
}

function stop {
    SHOST=`grep hostname $CONF | sed 's/ //g' | awk 'BEGIN {FS="="}{print $2}'`
    SPORT=`grep shutdownPort $CONF | sed 's/ //g' | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z "$SPORT" ]; then
      SPORT=8153
    fi
    
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemonAdminCLI' "shutdown" $SHOST $SPORT
}

function print_help {
   echo "PDP control script"
   echo ""
   echo "Usage:"
   echo "  pdpctl.sh status  - print PDP status"
   echo "  pdpctl.sh start   - to start the service"
   echo "  pdpctl.sh stop    - to stop the service" 
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'status') status;;
  'start') start;;
  'stop') stop;;
  *) print_help ;;
esac