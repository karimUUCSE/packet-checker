package com.irinfo.web;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;

import java.net.InetAddress;

public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("Pcap4J loaded");
        System.out.println(Pcaps.libVersion());

        PcapNetworkInterface nif =
                Pcaps.getDevByName("enp0s31f6");

        if (nif == null) {
            System.out.println("Interface not found");
            return;
        }

        PcapHandle handle =
                nif.openLive(
                        65536,
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        50
                );

        System.out.println("Waiting for packets...");

        int count = 0;

        while (true) {

            var packet = handle.getNextPacket();

            if (packet == null) {
                continue;
            }

            count++;

            System.out.println("\n=================================");
            System.out.println("Packet #" + count);
            System.out.println("Size: " + packet.length() + " bytes");

            IpPacket ip = packet.get(IpPacket.class);

            if (ip == null) {
                System.out.println("Non-IP Packet");
                continue;
            }

            InetAddress src = ip.getHeader().getSrcAddr();
            InetAddress dst = ip.getHeader().getDstAddr();

            System.out.println("Source IP      : " + src.getHostAddress());
            System.out.println("Destination IP : " + dst.getHostAddress());

            try {
                String host = dst.getCanonicalHostName();

                if (!host.equals(dst.getHostAddress())) {
                    System.out.println("Destination Host: " + host);
                }
            }
            catch (Exception ignored) {
            }

            System.out.println(
                    "Protocol: "
                            + ip.getHeader().getProtocol()
            );
        }
    }
}
