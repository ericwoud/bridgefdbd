#!/bin/bash

trap 'echo -n' SIGTSTP SIGTERM

while read BRIDGE FROM INFO MAC JUNK
do
  case $INFO in
     '<3>AP-STA-DISCONNECTED')      
          echo BRIDGEFDBDO $BRIDGE $FROM $INFO $MAC
          ;;
     '<3>AP-STA-CONNECTED')      
          echo BRIDGEFDBDO $BRIDGE $FROM $INFO $MAC
          ;;
     'EXIT')
          echo BRIDGEFDBDO EXIT 
          exit 0
          ;;
  esac
done


