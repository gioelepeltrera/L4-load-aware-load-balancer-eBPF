#!/bin/bash

# Define the commands to run in each pane
CMD1="sudo ip netns exec ns1 ./l4_lb "
CMD2="sudo su -c 'cat /sys/kernel/debug/tracing/trace_pipe'"

# Start a new tmux session with two panes executing different commands
tmux new-session -d -s my_session
tmux send-keys "$CMD1" C-m
tmux split-window -h
tmux send-keys "$CMD2" C-m
tmux attach -t my_session
