package com.irinfo.web;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.Scanner;

public class Main {

    private static volatile boolean isRunning = true;

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================================================================");
        System.out.println("  PACKET SNIFFER AUDIT TOOL | Pcap4J Engine: " + Pcaps.libVersion());
        System.out.println("===========================================================================================");

        File outputDir = new File("captures/output");
        File inputDir = new File("captures/input");

        if (!outputDir.exists()) outputDir.mkdirs();
        if (!inputDir.exists()) inputDir.mkdirs();

        // Interactive console input check
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Do you want to read an offline PCAP file? (y/n): ");
        String choice = inputScanner.nextLine().trim().toLowerCase();

        if (choice.equals("y") || choice.equals("yes")) {
            runOfflineReader(inputDir);
        } else {
            runLiveSniffer(new File(outputDir, "output_capture.pcap").getAbsolutePath());
        }
    }

    private static void runLiveSniffer(String savePath) throws Exception {
        PcapNetworkInterface nif = null;
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            String name = dev.getName().toLowerCase();
            // Secure selection: Active interfaces only, rejecting loopback footprints
            if (!dev.getAddresses().isEmpty() && !dev.isLoopBack() && !name.startsWith("lo")) {
                nif = dev;
                break;
            }
        }

        if (nif == null) {
            System.out.println("[ERROR] Active network interface not found. Ensure Wi-Fi or Ethernet is connected.");
            return;
        }

        System.out.println("\n[DEVICE METADATA]");
        System.out.println("Interface Name : " + nif.getName());
        if (!nif.getLinkLayerAddresses().isEmpty()) {
            System.out.println("Hardware MAC   : " + nif.getLinkLayerAddresses().get(0));
        }
        System.out.println("-------------------------------------------------------------------------------------------");

        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        PcapDumper dumper = handle.dumpOpen(savePath);

        startLinuxCacheListener();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            isRunning = false;
            try {
                Thread.sleep(120);
                System.out.println("\n[SHUTDOWN] PCAP stream sealed cleanly.");
                dumper.close();
                handle.close();
            } catch (Exception e) {
                System.out.println("Shutdown exception handled: " + e.getMessage());
            }
        }));

        System.out.println("[LIVE MODE] Sniffing active... Saving to: " + savePath);
        printDashboardHeader();

        int count = 0;
        while (isRunning) {
            Packet packet = handle.getNextPacket();
            if (packet == null) continue;
            if (!isRunning) break;

            count++;
            dumper.dump(packet, handle.getTimestamp());
            processAndPrintSingleLine(packet, count);
        }
    }

    private static void startLinuxCacheListener() {
        Thread cacheThread = new Thread(() -> {
            try {
                Process process = new ProcessBuilder("journalctl", "-u", "systemd-resolved.service", "-f", "-n", "0").start();
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;

                while (isRunning && (line = reader.readLine()) != null) {
                    if (line.contains("Using cached zone data") || line.contains("cache-hit")) {
                        String domain = "Unknown Domain";
                        if (line.contains("zone data for")) {
                            domain = line.substring(line.indexOf("zone data for") + 14).trim().split(" ")[0];
                        }
                        System.out.printf("[SYSTEM] | OS-CACHE | ---------- | LOCAL RAM MEMORY CACHE               | [HIT] %s\n", domain);
                        System.out.flush();
                    }
                }
                process.destroy();
            } catch (Exception ignored) {}
        });
        cacheThread.setDaemon(true);
        cacheThread.start();
    }

    private static void runOfflineReader(File inputDir) throws Exception {
        File[] pcapFiles = inputDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".pcap"));

        if (pcapFiles == null || pcapFiles.length == 0) {
            System.out.println("\n[ERROR] No .pcap logs discovered inside: " + inputDir.getAbsolutePath());
            return;
        }

        File fileToRead = pcapFiles[0];
        System.out.println("\n[READ MODE] Processing: " + fileToRead.getName());
        printDashboardHeader();

        PcapHandle handle = Pcaps.openOffline(fileToRead.getAbsolutePath());

        int count = 0;
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet == null) break;
            count++;
            processAndPrintSingleLine(packet, count);
        }

        handle.close();
        System.out.println("-------------------------------------------------------------------------------------------");
        System.out.println("[READ MODE] Processing finalized. Absolute Packet Count: " + count);
    }

    private static void printDashboardHeader() {
        System.out.println("-------------------------------------------------------------------------------------------");
        System.out.printf("%-8s | %-8s | %-10s | %-38s | %s\n", "INDEX", "PROTO", "SIZE", "ROUTING (SRC -> DST)", "INFO SUMMARY");
        System.out.println("-------------------------------------------------------------------------------------------");
    }

    private static void processAndPrintSingleLine(Packet packet, int count) throws Exception {
        String protoStr = "UNKNOWN";
        String routingStr = "Local / Link-Layer Data";
        String infoSummary = "Raw Frame Payload";

        IpPacket ip = packet.get(IpPacket.class);
        TcpPacket tcp = packet.get(TcpPacket.class);
        UdpPacket udp = packet.get(UdpPacket.class);

        if (ip != null) {
            protoStr = translateProtocol(ip.getHeader().getProtocol().toString());

            InetAddress src = ip.getHeader().getSrcAddr();
            InetAddress dst = ip.getHeader().getDstAddr();
            routingStr = String.format("%-15s -> %-15s", src.getHostAddress(), dst.getHostAddress());

            if (tcp != null) {
                infoSummary = String.format("Ports: %d->%d [SEQ:%d]", tcp.getHeader().getSrcPort().valueAsInt(), tcp.getHeader().getDstPort().valueAsInt(), tcp.getHeader().getSequenceNumber());
            } else if (udp != null) {
                infoSummary = String.format("Ports: %d->%d", udp.getHeader().getSrcPort().valueAsInt(), udp.getHeader().getDstPort().valueAsInt());
            }

            DnsPacket dns = packet.get(DnsPacket.class);
            if (dns != null && !dns.getHeader().getQuestions().isEmpty()) {
                protoStr = "DNS";
                String domain = dns.getHeader().getQuestions().get(0).getQName().getName();
                infoSummary = (dns.getHeader().isResponse() ? "[RES] " : "[REQ] ") + domain;
            }
        }

        if (tcp != null && tcp.getPayload() != null) {
            byte[] applicationData = tcp.getPayload().getRawData();
            String cleanAscii = extractReadableAscii(applicationData);
            if (!cleanAscii.isEmpty()) {
                infoSummary += " | Data snippet: " + cleanAscii;
            }
        }

        System.out.printf("[%6d] | %-8s | %4d bytes | %-38s | %s\n",
                count, protoStr, packet.length(), routingStr, infoSummary);
        System.out.flush();
    }

    private static String translateProtocol(String rawProto) {
        String clean = rawProto.split(" ")[0].toUpperCase();
        if (clean.equals("6")) return "TCP";
        if (clean.equals("17")) return "UDP";
        if (clean.equals("58")) return "ICMPv6";
        if (clean.equals("1")) return "ICMP";
        return clean;
    }

    private static String extractReadableAscii(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            }
        }
        String text = sb.toString().trim();
        if (text.length() > 15) {
            return text.substring(0, 5) + "..." + text.substring(text.length() - 5);
        }
        return text;
    }
}
