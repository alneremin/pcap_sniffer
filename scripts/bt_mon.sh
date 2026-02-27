#!/bin/bash

INTERVAL=${1:-1}
OUTPUT=${2:-"../outputs/test/bt/output_$(date +%s).csv"}

echo "Interval: $INTERVAL seconds"
echo "Output file: $OUTPUT"

# timestamp_nsecs,total_bytes

rm -f /tmp/btmon_pipe

sudo btmon | while read line; do
    echo "$line" >> /tmp/btmon_pipe
done &
BTMON_PID=$!

echo "btmon PID: $BTMON_PID"

cleanup() {
    echo "Stopping btmon(PID: $BTMON_PID)"
    kill $BTMON_PID 2>/dev/null
    rm -f /tmp/btmon_pipe
    exit 0
}

trap cleanup SIGINT SIGTERM

prev_total=0

while true; do
    if [ -f /tmp/btmon_pipe ]; then
        total=$(grep "ACL Data" /tmp/btmon_pipe | grep "dlen" | grep -o 'dlen [0-9]*' | cut -d' ' -f2 | paste -sd+ | bc)
        
        total=${total:-0}
        diff=$((total-prev_total))
        timestamp=$(date +%s%N)
        
        echo "$timestamp,$diff" >> "$OUTPUT"
        
        echo "[$(date +%H:%M:%S)]: $diff bytes"
  
  prev_total=$total
    else
        echo "Waiting for creating /tmp/btmon_pipe..."
    fi
    
    sleep $INTERVAL
done
