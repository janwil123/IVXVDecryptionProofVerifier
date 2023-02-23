# IVXV Decryption Proof Verifier

This project contains an independently developed decryption proof verifier for the IVXV Internet voting system. The verifier is written in the [Go programming language](https://go.dev/). The motivation to select Go includes the following considerations.

- The official decryption proof verifier is developed in Java, so an alternative verifier should be using something different.
- Go has a rich standard library including big integer arithmetic, support for ASN.1 parsing, etc.
- Go has high performance and is very good at multi-threading.

## Setting up the environment

In order to compile and run the verifier application, you need to install the Go environment first. For example, on Ubuntu you can write

    sudo apt install golang

On Ubuntu 22.04.1 LTS, this will install Go version 1.18 which is recent enough to use the application.

## Compiling and running the verifier

In order to compile the application, write

    go build ProofChecker.go

This will produce the `ProofChecker` binary. 

In order for the application to run. it needs access to two data files:

- public key used to encrypt the votes, and
- the zero-knowledge proofs exported by the tallying application.

Locations of these files can be configured in the `config.json` file. Once you are satisfied with its contents, run

    ./ProofChecker

and the process will begin. It is recommended to use a computer with a CPU supporting at least 16 threads.

## Example test files

The directory `RK2023_LIVE` contains example files originating from the live test run of 2023 parliamentary elections. The proofs file contains only 69 items which is not sufficient for stress testing. Hence, the directory also contains the Python script `multiply_proofs.py` that copies the items 4000 times. Feel free to play around with it.