#!/bin/bash

# Start MassPing node 1
# Usage: ./start_node.sh node1 192.168.1.10

NODE_NAME=${1:-node1}
NODE_HOST=${2:-127.0.0.1}
NODE="${NODE_NAME}@${NODE_HOST}"

echo "Starting MassPing node: $NODE"

# Set cookie for cluster authentication
COOKIE="massping_cluster"

# Start Erlang with distributed mode
erl -pa _build/default/lib/*/ebin \
    -name "$NODE" \
    -setcookie "$COOKIE" \
    -config config/massping.config \
    -s massping \
    -eval "io:format('MassPing node ~p started~n', [node()])."
