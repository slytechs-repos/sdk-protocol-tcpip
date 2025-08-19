/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.protocol.tcpip.ip;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import com.slytechs.jnet.core.api.format.HexDump;
import com.slytechs.jnet.core.api.format.HexDump.Column;
import com.slytechs.jnet.core.api.format.HexParser;
import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.protocol.api.Packet;
import com.slytechs.jnet.protocol.api.address.VlanId;
import com.slytechs.jnet.protocol.api.descriptor.QuickPacketDescriptor;
import com.slytechs.jnet.protocol.tcpip.Tcpip;
import com.slytechs.jnet.protocol.tcpip.ethernet.EtherTypes;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.ethernet.Vlan;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class IpTest {

	/**
	 * 
	 */
	public IpTest() {
		// TODO Auto-generated constructor stub
	}

	public static void testPacket() {
		byte[] bytes = HexParser.parseHex(
				"00 11 22 33 44 55 aa bb cc dd ee ff 81 00", // Eth
				"00 64 08 00", // VLAN (TCI + next EtherType for correct structure)
				"45 00 00 3c 30 39 40 00 40 06 3e d9 c0 a8 01 01 0a 00 00 01", // Ip4
				"30 39 00 50 00 00 00 01 00 00 00 00 50 02 ff ff 61 ab 00 00", // Tcp
				"48 65 6c 6c 6f 20 57 6f 72 6c 64 21 00 00 00 00 00 00 00 00" // Payload
		);

		Packet packet = new Packet();
		QuickPacketDescriptor quick = new QuickPacketDescriptor();
		Ethernet ethernet = new Ethernet();
		Ip4 ip4 = new Ip4();
		Ip6 ip6 = new Ip6();

		try (Arena arena = Arena.ofShared()) {
			MemorySegment mdesc = arena.allocate(QuickPacketDescriptor.LAYOUT);
			MemorySegment mbuf = arena.allocate(bytes.length);
			MemorySegment.copy(bytes, 0, mbuf, ValueLayout.JAVA_BYTE, 0, bytes.length);

			quick.bindMemory(Memory.of(mdesc, 0), 0);
			quick.setCaptureLength(bytes.length);
			quick.setWireLength(bytes.length);
			quick.setCount(4);

			long bitmask = Ethernet.ID % 64;
			bitmask |= Vlan.ID % 64;
			bitmask |= Ip4.ID % 64;
			bitmask |= Tcpip.TCP_ID % 64;
			quick.setBitmask(bitmask);

			int offset = 0;
			offset += quick.setRecordAt(0, Ethernet.ID, offset, Ethernet.LENGTH);
			offset += quick.setRecordAt(1, Vlan.ID, offset, Vlan.LENGTH);
			offset += quick.setRecordAt(2, Ip4.ID, offset, Ip4.LENGTH);
			offset += quick.setRecordAt(3, Tcpip.TCP_ID, offset, 20);

			System.out.println(HexDump.dump(mbuf.asByteBuffer()));

			packet.bindMemory(Memory.of(mbuf, 0), 0);
			packet.setPacketDescriptor(quick);

			if (packet.hasHeader(ethernet))
				System.out.println(ethernet);

			if (packet.hasHeader(ip4))
				System.out.println(ip4);

			if (packet.hasHeader(ip6))
				System.out.println(ip6);

			System.out.println(quick);

		}
	}

	public static void main(String[] args) {

		testPacket();
	}

	public static void testHeaders() {
		// Existing IP tests
		Ip4 ipV4 = new Ip4(Arena.ofAuto());
		Ip6 ipV6 = new Ip6(Arena.ofAuto());

		// Set up realistic IPv4 header
		ipV4.setVersionIhl(4, 5);
		ipV4.setTos(0);
		ipV4.setLength(60);
		ipV4.setId(12345);
		ipV4.setFlags(Ip4Flags.nonFragmented());
		ipV4.setTtl(64);
		ipV4.setProtocol(6);
		ipV4.setSrcFromString("192.168.1.1");
		ipV4.setDstFromString("10.0.0.1");

		// Set up realistic IPv6 header
		ipV6.setVersion(6);
		ipV6.setTrafficClass(0);
		ipV6.setFlowLabel(0x12345);
		ipV6.setPayloadLength(1024);
		ipV6.setNextHeader(6);
		ipV6.setHopLimit(64);
		ipV6.setSrcFromString("::1");
		ipV6.setDstFromString("::1");

		// Existing Ethernet tests
		Ethernet eth = new Ethernet(Arena.ofAuto());
		eth.setSrcFromString("aa:bb:cc:dd:ee:ff");
		eth.setDstFromString("00:11:22:33:44:55");
		eth.setEtherType(EtherTypes.IPV4);

		// NEW: Add VLAN header tests
		Vlan vlan = new Vlan(Arena.ofAuto());

		// Set up realistic VLAN tag
		vlan.setTpid(EtherTypes.VLAN); // Standard 802.1Q
		vlan.setTci(6, false, 100); // Voice priority, no drop, VLAN 100

		System.out.println("=== Populated Headers ===");
		System.out.println(ipV4);
		System.out.println(ipV6);
		System.out.println(eth);
		System.out.println(vlan); // NEW

		System.out.println("\n=== Hex Dumps ===");
		System.out.println("IPv4:");
		System.out.println(HexDump.dump(ipV4.asByteBuffer(), Column.OFFSET, Column.HEX, Column.ASCII));

		System.out.println("\nIPv6:");
		System.out.println(HexDump.dump(ipV6.asByteBuffer()));

		System.out.println("\nEthernet:");
		System.out.println(HexDump.dump(eth.asByteBuffer()));

		// NEW: VLAN hex dump
		System.out.println("\nVLAN:");
		System.out.println(HexDump.dump(vlan.asByteBuffer()));

		// Existing Ethernet frame types
		System.out.println("\n=== Ethernet Frame Types ===");

		Ethernet ethIpv6 = new Ethernet(Arena.ofAuto());
		ethIpv6.setSrcFromString("11:22:33:44:55:66");
		ethIpv6.setDstFromString("ff:ff:ff:ff:ff:ff");
		ethIpv6.setEtherType(EtherTypes.IPV6);
		System.out.println("IPv6 Frame: " + ethIpv6);

		Ethernet ethArp = new Ethernet(Arena.ofAuto());
		ethArp.setSrcFromString("aa:bb:cc:dd:ee:ff");
		ethArp.setDstFromString("01:00:5e:00:00:01");
		ethArp.setEtherType(EtherTypes.ARP);
		System.out.println("ARP Frame: " + ethArp);

		Ethernet eth8023 = new Ethernet(Arena.ofAuto());
		eth8023.setSrcFromString("12:34:56:78:9a:bc");
		eth8023.setDstFromString("de:ad:be:ef:ca:fe");
		eth8023.setEtherType(1500);
		System.out.println("802.3 Frame: " + eth8023);

		// NEW: VLAN frame types and configurations
		System.out.println("\n=== VLAN Configurations ===");

		// Voice VLAN
		Vlan voiceVlan = new Vlan(Arena.ofAuto());
		voiceVlan.setTpid(EtherTypes.VLAN);
		voiceVlan.setTci(6, false, 200); // Voice priority, VLAN 200
		System.out.println("Voice VLAN: " + voiceVlan);

		// Data VLAN with drop eligibility
		Vlan dataVlan = new Vlan(Arena.ofAuto());
		dataVlan.setTpid(EtherTypes.VLAN);
		dataVlan.setTci(3, true, 300); // Critical Apps, drop-eligible, VLAN 300
		System.out.println("Data VLAN: " + dataVlan);

		// QinQ outer tag
		Vlan qinqOuter = new Vlan(Arena.ofAuto());
		qinqOuter.setTpid(EtherTypes.QINQ_OUTER); // 802.1ad outer tag
		qinqOuter.setTci(7, false, 10); // Network Control, VLAN 10
		System.out.println("QinQ Outer: " + qinqOuter);

		// QinQ inner tag
		Vlan qinqInner = new Vlan(Arena.ofAuto());
		qinqInner.setTpid(EtherTypes.QINQ_INNER); // Inner tag (0x8100)
		qinqInner.setTci(0, false, 500); // Best effort, VLAN 500
		System.out.println("QinQ Inner: " + qinqInner);

		// Existing frame classification
		System.out.println("\n=== Frame Classification ===");
		System.out.println("IPv4 frame - Unicast: " + eth.isUnicast());
		System.out.println("IPv6 frame - Broadcast: " + ethIpv6.isBroadcast());
		System.out.println("ARP frame - Multicast: " + ethArp.isMulticast());
		System.out.println("802.3 frame - Is Length: " + eth8023.isLength());
		System.out.println("IPv4 frame - Is EtherType: " + eth.isEtherType());

		// NEW: VLAN classification
		System.out.println("\n=== VLAN Classification ===");
		System.out.println("Voice VLAN - High Priority: " + voiceVlan.isHighPriority());
		System.out.println("Voice VLAN - Traffic Class: " + voiceVlan.getTrafficClass());
		System.out.println("Data VLAN - Valid VID: " + dataVlan.isValidVid());
		System.out.println("Data VLAN - DEI: " + dataVlan.dei());
		System.out.println("QinQ Outer - Is QinQ: " + qinqOuter.isQinQOuter());
		System.out.println("QinQ Inner - Is Standard: " + qinqInner.isStandardVlan());

		// NEW: VLAN ID address object access
		System.out.println("\n=== VLAN Address Objects ===");
		VlanId voiceTci = voiceVlan.tci();
		System.out.println("Voice TCI as address: " + voiceTci);
		System.out.println("Voice VID from address: " + voiceTci.vid());
		System.out.println("Voice PCP from address: " + voiceTci.pcp());

		// Existing hex dumps
		System.out.println("\n=== Different Frame Hex Dumps ===");
		System.out.println("Broadcast IPv6:");
		System.out.println(HexDump.dump(ethIpv6.asByteBuffer(), Column.HEX, Column.ASCII));

		System.out.println("\nMulticast ARP:");
		System.out.println(HexDump.dump(ethArp.asByteBuffer(), Column.ASCII, Column.HEX, Column.ASCII));

		System.out.println("\n802.3 Length Field:");
		System.out.println(HexDump.dumpCompact(eth8023.asByteBuffer()));

		// NEW: VLAN hex dumps with different formats
		System.out.println("\n=== VLAN Hex Dumps ===");
		System.out.println("Voice VLAN (Standard):");
		System.out.println(HexDump.dump(voiceVlan.asByteBuffer()));

		System.out.println("\nQinQ Stack (Compact):");
		System.out.println(HexDump.dumpCompact(qinqOuter.asByteBuffer()));
		System.out.println(HexDump.dumpCompact(qinqInner.asByteBuffer()));

		System.out.println("\nData VLAN (HEX Only):");
		System.out.println(HexDump.dumpHexOnly(dataVlan.asByteBuffer()));

	}
}
