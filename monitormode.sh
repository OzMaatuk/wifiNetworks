#!/bin/bash

ifconfig $1 down
#iw dev $1 set type managed
iw dev $1 set type monitor
ifconfig $1 up
sleep 2
