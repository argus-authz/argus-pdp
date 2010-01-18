#! /bin/bash

# This script starts and stop the PDP daemon.

HOME="$(cd "${0%/*}/.." && pwd)"
CONF="$HOME/conf/pdp.ini"

# Source our environment setup script
. $HOME/sbin/env.sh

# Add the PDP home directory property
JVMOPTS="-Dorg.glite.authz.pdp.home=$HOME $JVMOPTS"
    
function executeAdminCommand {
    HOST=`sed 's/ //g' $CONF | grep "^adminHost" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z $HOST ] ; then
       HOST="127.0.0.1"
    fi

    PORT=`sed 's/ //g' $CONF | grep "^adminPort" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z $PORT ] ; then
       PORT="8153"
    fi
    
    PASS=`sed 's/ //g' $CONF | grep "^adminPassword" | awk 'BEGIN {FS="="}{print $2}'`
    
    
    $JAVACMD $JVMOPTS 'org.glite.authz.common.http.JettyAdminServiceCLI' $HOST $PORT $1 $PASS
}

function start {
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pdp.server.PDPDaemon' $CONF &
}

function print_help {
   echo "PDP control script"
   echo ""
   echo "Usage:"
   echo "  $0 start   - to start the service"
   echo "  $0 stop    - to stop the service" 
   echo "  $0 status  - print PDP status"
   echo "  $0 reloadPolicy - reloads the policy from the PAP"
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'start') start;;
  'stop') executeAdminCommand 'shutdown' ;;
  'status') executeAdminCommand 'status' ;;
  'reloadPolicy') executeAdminCommand 'reloadPolicy' ;;
  *) print_help ;;
esac
