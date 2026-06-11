# Network Packet Reader & Sniffer Audit Tool (MVP)

A lightweight, hybrid network packet parsing and local OS cache auditing engine built with **Java 26** and **Maven**. This project operates as a high-performance Minimum Viable Product (MVP) designed to inspect raw network frames, parse core protocols, and concurrently analyze local operating system DNS caching behaviors.

> **Tagline:** A lightweight Java 26 CLI tool for parsing, inspecting, and auditing network packets.

---

## 🚀 Features

### 1. Dual-Mode Input

* **What it does:** It can watch live network events as they happen or replay recorded history.
* **How it works:** Features an interactive startup menu. Choose **Live Mode** to sniff, display, and record active wire data, or select **Review Mode** to feed it an existing packet capture log (`.pcap`) to reconstruct the dashboard timeline step-by-step.

### 2. "Plug and Play" Active Interface Detection

* **What it does:** Bypasses tedious manual device configurations or typing complex hardware card names.
* **How it works:** Upon live startup, the engine scans all available physical hardware assets, targeting the machine's active pathway to the internet (Wi-Fi or Ethernet). It gracefully ignores virtual loopback devices to keep your stream clear of internal static.

### 3. "Double-Check" Domain Spy

* **What it does:** Intercepts domain requests even when your operating system tries to hide them inside localized short-term memory caches.
* **How it works:** When a website is visited repeatedly, the OS pulls data from short-term RAM rather than sending a fresh packet over the wire—leaving normal sniffers completely blind. This tool spawns an asynchronous worker thread to trace the native OS journal pipeline, flagging localized `[SYSTEM]` cache hits in real-time alongside network traffic.

### 4. Smart Payload Translator

* **What it does:** Extracts human-readable information from raw, ugly binary numbers and hex data structures.
* **How it works:** Translates raw protocol integer identifiers on the fly (e.g., `6` $\rightarrow$ `TCP`, `17` $\rightarrow$ `UDP`). It handles malformed frames gracefully and targets application data layers directly to securely output clean ASCII text snippets (such as raw HTTP web headers or `HTML>` tags).

### 5. "Emergency Brake" Lifecycle Hook

* **What it does:** Safely closes file streams when you exit the app, preventing output file corruption.
* **How it works:** Forcefully killing terminal tools usually ruins open `.pcap` files. This tool hooks deep into the JVM runtime lifecycle. The moment a shutdown signal is received, it pauses processing frames for a fraction of a second, flushes pending buffers, seals the active log cleanly, and releases the hardware hook without race conditions.

---

## 📊 Dashboard Spacing Matrix

The application utilizes a synchronized, fixed-width formatting matrix (`%-8s | %-8s | %-10s | %-38s | %s`) to ensure live wire packet rows and asynchronous localized OS cache hits seamlessly interlace without breaking terminal layout boundaries.

```text
INDEX    | PROTO    | SIZE       | ROUTING (SRC -> DST)                   | INFO SUMMARY
-------------------------------------------------------------------------------------------
[     1] | DNS      |   72 bytes | 192.168.20.206  -> 8.8.8.8             | [REQ] wikipedia.org
[     2] | DNS      |   88 bytes | 8.8.8.8         -> 192.168.20.206      | [RES] wikipedia.org
[     3] | ICMP     |   98 bytes | 192.168.20.206  -> 208.80.154.224      | Ports: 0->0
[SYSTEM] | OS-CACHE | ---------- | LOCAL RAM MEMORY CACHE               | [HIT] wikipedia.org
[     4] | TCP      |   74 bytes | 192.168.20.206  -> 142.250.67.238      | Ports: 41402->80 [SEQ:654531170]
[     5] | TCP      |  839 bytes | 142.250.67.238  -> 192.168.20.206      | Ports: 80->41402 | Data snippet: HTML>

```

---

## 🛠️ Project Architecture

The application bifurcates processing and sorting mechanics across three distinct architectural layers:

1. **Network Interface Layer (JNI):** Binds securely to native network adapters using Java Native Interface bindings via Pcap4J to manage promiscuous state capture.
2. **Protocol Demultiplexing Layer:** Dissects raw frames down to IPv4/IPv6 headers, determines underlying protocol maps, and extracts key metadata fields (Source/Destination IPs, Ports, Packet Length, and Sequence boundaries).
3. **OS System Log Pipeline:** Spawns a background daemon listening directly to Linux's system-level `systemd-resolved.service` log pipeline to cross-examine hardware metrics against OS cache performance.

---

## ⚙️ Installation & Prerequisites

### Environments & Tools

* **Operating System:** Linux (Ubuntu/Debian distributions thoroughly tested)
* **Java Development Kit:** JDK 26
* **Build Automation:** Apache Maven
* **Native Dependency:** `libpcap`

Install the underlying native capture system libraries before running the project compiler:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev

```

### Granting Network Hardware Privileges

Because hook execution requests low-level access to network hardware adapters, standard non-root Java execution will fail. Explicitly attach raw network processing flags to your local Java binary setup using `setcap`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which java))

```

---

## 🚀 Running the Tool

### Compilation

Clone the repository and compile using the Maven wrapper:

```bash
git clone git@github.com:karimUUCSE/packet-checker.git
cd packet-checker
mvn clean package

```

### Execution

Run the executable application JAR:

```bash
java -jar target/packet-checker-1.0-SNAPSHOT.jar

```

```text
===========================================================================================
  PACKET SNIFFER AUDIT TOOL | Pcap4J Engine: libpcap version 1.10.4
===========================================================================================
Do you want to read an offline PCAP file? (y/n): 

```

* **Enter `n` (No):** Initiates automated live hardware sniffing, binding directly to your active default network adapter and dropping stream dumps live to `captures/output/output_capture.pcap`.
* **Enter `y` (Yes):** Prompts the offline file processor to index, evaluate, and output historical packet logs dropped inside the local `captures/input/` folder.

---

## 📝 Directory Tree Structure

```text
packet-checker/
├── pom.xml                                 # Maven configuration tracking JDK 26 and Pcap4J
├── captures/
│   ├── input/                              # Storage vault for offline source .pcap files
│   └── output/                             # Destination for real-time live capture recordings
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── irinfo/
│                   └── web/
│                       └── Main.java       # Core application execution engine
├── .gitignore                              # Blocks local raw data pollution from repository history
└── README.md                               # System documentation and playbook

```

---

## 🔮 Future Roadmap Enhancements

* **Advanced Protocol Inspections:** Add deep application-layer inspection (HTTP/2, TLS handshake extraction).
* **Granular Packet Filtering:** Implement BPF (Berkeley Packet Filter) syntax support directly into the interactive CLI prompt.
* **Refactored Modular Architecture:** Distribute processing out of single-class architecture into dedicated `/parser`, `/model`, and `/cli` operational sub-packages.
* **Export Extensions:** Integrate structural serialization pipelines to export captured data to JSON and CSV formats.