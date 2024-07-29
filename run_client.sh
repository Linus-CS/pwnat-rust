#!/bin/bash
cargo build --release
sudo ./target/release/icmp-sockets -c --remote 79.235.139.236 
