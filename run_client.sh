#!/bin/bash
cargo build --release
sudo ./target/release/icmp-sockets -c
