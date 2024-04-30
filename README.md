# Bike-Scan - a scanning tool to scan ipsec server

## Purpose of this project
The purpose of this project is to scan ipsec servers reliably.
Bike-Scan finds all transformations of a server if it is configured with the ikev1 protocol.
In the case of a configuration with the Ikev2 protocol, the first transformation in the configured list is found but only if the diffie-hellman group of the key-exchange payload is 1024 bit modp.
Bike-Scan was developed as part of a bachelor thesis in collaboration with Trufflepig IT-Forensics GmbH.

## Tutorial (Linux)

## Prerequisites (if needed):
1. Download and install Rust (using rustup is recommended) on www.rust-lang.org/tools/install
2. Download and install cargo via package manager (e.g. sudo apt install cargo)
3. Download git via package manager (e.g. sudo apt install git)

## Download and Install:
1. git clone this repository in desired location
```
git clone https://github.com/trufflebee33/bike-scan.git
```
2. cd into cloned bike-scan folder
3. install using cargo
```
cargo install --path .
```

## HOW TO USE
1. Build a main function to use the scan method
2. If you want to run the version for ikeV1 use function scan. If you want to run the version for ikeV2 use function scan_v2
3. Insert the ip adress and port of the server you want to scan
4. Run your main function
