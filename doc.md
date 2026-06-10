# Network Packet Reader (Java)

## Overview

A Java-based command-line application that reads network packets as input and displays relevant packet information in a human-readable format.

## Goal

Build a lightweight packet inspection tool capable of parsing packet data and displaying essential network information through the command line.

## Technology Stack

* Java 26
* Maven
* CLI Application
* Optional future library: Pcap4J (for live packet capture)

## MVP Scope

### Input

* Accept raw packet data from a file, byte stream, or predefined packet samples.
* Validate packet structure before processing.

### Processing

* Parse network-layer information.
* Identify packet protocol.
* Extract relevant metadata.

### Output

```text
Packet Information
------------------
Source IP        : 192.168.1.10
Destination IP   : 8.8.8.8
Protocol         : TCP
Source Port      : 54321
Destination Port : 443
Packet Length    : 1500 bytes
```

## Core Features

* Read packet input.
* Parse IPv4 packets.
* Detect TCP, UDP, and ICMP protocols.
* Extract:

    * Source IP
    * Destination IP
    * Protocol
    * Packet Size
    * Ports (when applicable)
* Handle malformed packets gracefully.

## Suggested Project Structure

```text
packet-reader/
├── pom.xml
└── src/
    └── main/
        └── java/
            └── com/example/packetreader/
                ├── Main.java
                ├── parser/
                │   └── PacketParser.java
                ├── model/
                │   └── PacketInfo.java
                └── cli/
                    └── PacketPrinter.java
```

## Future Enhancements

* Live packet capture from network interfaces.
* PCAP file support.
* Packet filtering.
* Protocol-specific deep inspection.
* Statistics dashboard.
* JSON/CSV export.
* Interactive CLI commands.

## Success Criteria

The application successfully accepts packet data, parses essential network information, and displays readable packet details in the terminal using Java 26 and Maven.

## Tagline

> A lightweight Java 26 CLI tool for parsing and inspecting network packets.
