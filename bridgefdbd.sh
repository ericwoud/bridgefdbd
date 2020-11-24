#!/bin/bash

trap 'echo -n' SIGTSTP SIGTERM

while read DEVICE FROM INFO MAC JUNK
do
  case $INFO in
     'AP-STA-DISCONNECTED')      
          echo BRIDGEFDBDO $DEVICE $FROM $INFO $MAC
          ;;
     'AP-STA-CONNECTED')      
          echo BRIDGEFDBDO $DEVICE $FROM $INFO $MAC
          ;;
     'EXIT')
          echo BRIDGEFDBDO EXIT 
          exit 0
          ;;
  esac
done


