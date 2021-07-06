#!/bin/bash

trap 'echo -n' SIGTSTP SIGTERM

while read IP DEVICE EVENT
do
  case $EVENT in
     AP-STA-DISCONNECTED*)      
          echo BRIDGEFDBDO I=$IP D=$DEVICE E=$EVENT
          ;;
     AP-STA-CONNECTED*)      
          echo BRIDGEFDBDO I=$IP D=$DEVICE E=$EVENT
          ;;
     EXIT)
          echo BRIDGEFDBDO EXIT 
          exit 0
          ;;
  esac
done


