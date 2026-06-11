package com.irinfo.web;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.File;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("=================================================");
        System.out.println("Network Packet Reader");
        System.out.println("Pcap Version: " + Pcaps.libVersion());
        System.out.println("=================================================");

        File inputDir = new File("captures/input");
        File outputDir = new File("captures/output");

        if (!inputDir.exists()) {
            inputDir.mkdirs();
        }

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        Scanner scanner = new Scanner(System.in);

        System.out.println();
        System.out.println("1 - Live Capture");
        System.out.println("2 - Read PCAP File");
        System.out.print("Choose mode: ");

        String mode = scanner.nextLine().trim();

        PacketProcessor processor = new PacketProcessor();

        PacketReader reader =
                new PacketReader(processor);

        if ("2".equals(mode)) {
            reader.readOfflinePcap(inputDir);
        }
        else {
            reader.runLiveCapture(outputDir);
        }
    }

    static class PacketReader {

        private final PacketProcessor processor;

        private volatile boolean running = true;

        public PacketReader(PacketProcessor processor) {

            this.processor = processor;
        }

        public void runLiveCapture(File outputDir)
                throws Exception {

            PcapNetworkInterface nif = null;

            for (PcapNetworkInterface dev :
                    Pcaps.findAllDevs()) {

                if (!dev.isLoopBack()
                        && !dev.getAddresses().isEmpty()) {

                    nif = dev;
                    break;
                }
            }

            if (nif == null) {

                System.out.println(
                        "No active network interface found."
                );

                return;
            }

            System.out.println();
            System.out.println(
                    "Using Interface: "
                            + nif.getName()
            );

            PcapHandle handle =
                    nif.openLive(
                            65536,
                            PcapNetworkInterface
                                    .PromiscuousMode
                                    .PROMISCUOUS,
                            50
                    );

            String outputFile =
                    new File(
                            outputDir,
                            "capture-"
                                    + System.currentTimeMillis()
                                    + ".pcap"
                    ).getAbsolutePath();

            PcapDumper dumper =
                    handle.dumpOpen(outputFile);

            Runtime.getRuntime()
                    .addShutdownHook(
                            new Thread(() -> {

                                running = false;

                                try {

                                    dumper.close();
                                    handle.close();

                                } catch (Exception ignored) {
                                }

                                System.out.println();
                                System.out.println(
                                        "Capture saved to:"
                                );
                                System.out.println(
                                        outputFile
                                );
                            })
                    );

            System.out.println();
            System.out.println(
                    "Waiting for packets..."
            );
            System.out.println();

            int count = 0;

            while (running) {

                Packet packet =
                        handle.getNextPacket();

                if (packet == null) {
                    continue;
                }

                count++;

                dumper.dump(
                        packet,
                        handle.getTimestamp()
                );

                processor.process(
                        packet,
                        count
                );
            }
        }

        public void readOfflinePcap(
                File inputDir
        ) throws Exception {

            File[] files =
                    inputDir.listFiles(
                            (dir, name) ->
                                    name.endsWith(".pcap")
                                            || name.endsWith(".cap")
                    );

            if (files == null
                    || files.length == 0) {

                System.out.println();
                System.out.println(
                        "No PCAP files found in:"
                );
                System.out.println(
                        inputDir.getAbsolutePath()
                );

                return;
            }

            File pcapFile =
                    files[0];

            System.out.println();
            System.out.println(
                    "Reading:"
            );
            System.out.println(
                    pcapFile.getAbsolutePath()
            );
            System.out.println();

            PcapHandle handle =
                    Pcaps.openOffline(
                            pcapFile.getAbsolutePath()
                    );

            int count = 0;

            while (true) {

                Packet packet =
                        handle.getNextPacket();

                if (packet == null) {
                    break;
                }

                count++;

                processor.process(
                        packet,
                        count
                );
            }

            handle.close();

            System.out.println();
            System.out.println(
                    "Finished."
            );
            System.out.println(
                    "Packets Processed: "
                            + count
            );
        }
    }

    static class PacketProcessor {

        private final DnsCache dnsCache =
                new DnsCache();

        public PacketProcessor() {

            printHeader();
        }

        private void printHeader() {

            System.out.println(
                    "------------------------------------------------------------------------------------------------------------------------");

            System.out.printf(
                    "%-8s %-10s %-18s %-18s %-10s %-40s %-15s%n",
                    "PACKET",
                    "PROTO",
                    "SOURCE",
                    "DESTINATION",
                    "SIZE",
                    "INFO",
                    "PAYLOAD"
            );

            System.out.println(
                    "------------------------------------------------------------------------------------------------------------------------");
        }

        public void process(Packet packet, int count) {

            String protocol = "UNKNOWN";
            String source = "-";
            String destination = "-";
            String info = "";
            String payloadPreview = "";

            IpPacket ip =
                    packet.get(IpPacket.class);

            if (ip != null) {

                InetAddress src =
                        ip.getHeader().getSrcAddr();

                InetAddress dst =
                        ip.getHeader().getDstAddr();

                source =
                        src.getHostAddress();

                destination =
                        dst.getHostAddress();

                DnsPacket dns =
                        packet.get(DnsPacket.class);

                if (dns != null) {

                    protocol = "DNS";

                    if (!dns.getHeader()
                            .getQuestions()
                            .isEmpty()) {

                        String domain =
                                dns.getHeader()
                                        .getQuestions()
                                        .get(0)
                                        .getQName()
                                        .getName();

                        if (dns.getHeader().isResponse()) {

                            info =
                                    "DNS Response: "
                                            + domain;

                        } else {

                            info =
                                    "DNS Query: "
                                            + domain;

                            dnsCache.put(
                                    destination,
                                    domain
                            );
                        }
                    }
                }

                else {

                    TcpPacket tcp =
                            packet.get(TcpPacket.class);

                    UdpPacket udp =
                            packet.get(UdpPacket.class);

                    IcmpV4CommonPacket icmp =
                            packet.get(IcmpV4CommonPacket.class);

                    if (tcp != null) {

                        protocol = "TCP";

                        info =
                                "Port "
                                        + tcp.getHeader()
                                        .getSrcPort()
                                        .valueAsInt()
                                        + " -> "
                                        + tcp.getHeader()
                                        .getDstPort()
                                        .valueAsInt();

                        if (tcp.getPayload() != null) {

                            payloadPreview =
                                    PayloadUtil.extractPreview(
                                            tcp.getPayload()
                                                    .getRawData()
                                    );
                        }
                    }

                    else if (udp != null) {

                        protocol = "UDP";

                        info =
                                "Port "
                                        + udp.getHeader()
                                        .getSrcPort()
                                        .valueAsInt()
                                        + " -> "
                                        + udp.getHeader()
                                        .getDstPort()
                                        .valueAsInt();

                        if (udp.getPayload() != null) {

                            payloadPreview =
                                    PayloadUtil.extractPreview(
                                            udp.getPayload()
                                                    .getRawData()
                                    );
                        }
                    }

                    else if (icmp != null) {

                        protocol = "ICMP";

                        String host = null;

                        if (dnsCache.contains(destination)) {

                            host =
                                    dnsCache.get(
                                            destination
                                    );
                        }

                        if (host != null) {

                            info =
                                    "Ping "
                                            + host;

                        } else {

                            info =
                                    "ICMP Packet";
                        }
                    }

                    else {

                        IpNumber ipNumber =
                                ip.getHeader()
                                        .getProtocol();

                        protocol =
                                ipNumber.toString();
                    }
                }
            }

            System.out.printf(
                    "%-8d %-10s %-18s %-18s %-10d %-40s %-15s%n",
                    count,
                    protocol,
                    source,
                    destination,
                    packet.length(),
                    info,
                    payloadPreview
            );
        }
    }

    static class DnsCache {

        private final Map<String, String> cache =
                new HashMap<>();

        public void put(String ip, String domain) {
            cache.put(ip, domain);
        }

        public String get(String ip) {
            return cache.get(ip);
        }

        public boolean contains(String ip) {
            return cache.containsKey(ip);
        }
    }

    static class PayloadUtil {

        public static String extractPreview(byte[] data) {

            if (data == null || data.length == 0) {
                return "";
            }

            StringBuilder sb = new StringBuilder();

            for (byte b : data) {

                if (b >= 32 && b <= 126) {
                    sb.append((char) b);
                }
            }

            String text = sb.toString().trim();

            if (text.isEmpty()) {
                return "";
            }

            if (text.length() <= 10) {
                return text;
            }

            return text;
        }
    }
}
