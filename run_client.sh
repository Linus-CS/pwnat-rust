#!/bin/bash
cargo build --release
sudo ./target/release/icmp-sockets -c --remote 79.216.187.96
