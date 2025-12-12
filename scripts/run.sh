#!/bin/bash

# Build and run MassPing
# Usage: ./run.sh

echo "Building MassPing..."
rebar3 compile

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Building escript..."
rebar3 escriptize

if [ $? -ne 0 ]; then
    echo "Escript build failed!"
    exit 1
fi

echo "Running tests..."
rebar3 eunit

echo ""
echo "MassPing built successfully!"
echo ""
echo "Usage examples:"
echo "  ./massping scan 192.168.1.0/24 -p 80,443,22"
echo "  ./massping scan 10.0.0.0/16 -p 80 --rate 50000"
echo ""
echo "Or start Erlang shell:"
echo "  rebar3 shell"
