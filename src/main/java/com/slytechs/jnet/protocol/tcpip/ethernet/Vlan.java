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
package com.slytechs.jnet.protocol.tcpip.ethernet;

import static com.slytechs.jnet.core.api.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.detail.DetailBuilder;
import com.slytechs.jnet.core.api.detail.Detailable;
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;
import com.slytechs.jnet.protocol.api.FixedHeader;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

import static java.lang.foreign.MemoryLayout.*;

/**
 * IEEE 802.1Q VLAN tag header.
 * 
 * <p>
 * VLAN (Virtual Local Area Network) tagging allows a single physical network
 * to be partitioned into multiple logical networks. The 802.1Q tag is inserted
 * into Ethernet frames between the source MAC address and the original
 * EtherType/Length field.
 * </p>
 * 
 * <h2>Header Format</h2>
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |PCP|D|         VID             |          EtherType            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Tag Control Information (TCI)</h2>
 * <ul>
 * <li><b>PCP</b> (3 bits) - Priority Code Point, IEEE 802.1p class of service</li>
 * <li><b>DEI</b> (1 bit) - Drop Eligible Indicator (formerly CFI)</li>
 * <li><b>VID</b> (12 bits) - VLAN Identifier (0-4095)</li>
 * </ul>
 * 
 * <h2>Special VID Values</h2>
 * <ul>
 * <li>0 - Priority tagged frame (no VLAN)</li>
 * <li>1 - Default VLAN</li>
 * <li>4095 (0xFFF) - Reserved</li>
 * </ul>
 * 
 * <h2>QinQ (802.1ad)</h2>
 * <p>
 * Double-tagged frames use TPID 0x88A8 for the outer (service) tag and 0x8100
 * for the inner (customer) tag. Each tag is parsed as a separate Vlan header.
 * </p>
 * 
 * {@snippet :
 * Vlan vlan = packet.getHeader(new Vlan());
 * 
 * System.out.println("VLAN ID: " + vlan.vid());
 * System.out.println("Priority: " + vlan.pcp());
 * System.out.println("Inner Type: " + EtherTypeResolver.resolveAbbr(vlan.etherType()));
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ethernet
 * @see EtherTypeResolver
 */
public class Vlan extends FixedHeader implements Detailable {

	/** Protocol ID for VLAN. */
	public static final int ID = Tcpip.Constants.VLAN_ID;

	/** VLAN header length in bytes. */
	public static final int HEADER_LENGTH = 4;

	/** TPID for standard 802.1Q VLAN tag. */
	public static final int TPID_8021Q = 0x8100;

	/** TPID for 802.1ad service VLAN (QinQ outer tag). */
	public static final int TPID_8021AD = 0x88A8;

	/** TPID for legacy QinQ (some vendors). */
	public static final int TPID_QINQ_LEGACY = 0x9100;

	/** VID for priority-tagged frames (no VLAN membership). */
	public static final int VID_PRIORITY = 0;

	/** Default VLAN ID. */
	public static final int VID_DEFAULT = 1;

	/** Reserved VID (must not be used). */
	public static final int VID_RESERVED = 0xFFF;

	/** Maximum valid VID. */
	public static final int VID_MAX = 4094;

	/** VLAN header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U16_BE.withName("hdr_tci"),
			U16_BE.withName("hdr_ethertype")
	);

	private static final ShortHandle TCI = new ShortHandle(LAYOUT, "hdr_tci");
	private static final ShortHandle ETHERTYPE = new ShortHandle(LAYOUT, "hdr_ethertype");

	private static final int PCP_MASK = 0xE000;
	private static final int PCP_SHIFT = 13;
	private static final int DEI_MASK = 0x1000;
	private static final int VID_MASK = 0x0FFF;

	/**
	 * Constructs a new VLAN header.
	 */
	public Vlan() {
		super(ID, LAYOUT);
	}

	/**
	 * Returns the Tag Control Information field (16 bits).
	 * 
	 * <p>
	 * The TCI contains PCP, DEI, and VID fields combined.
	 * </p>
	 *
	 * @return the raw TCI value
	 */
	public int tci() {
		return TCI.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the Tag Control Information field.
	 *
	 * @param tci the TCI value
	 */
	public void setTci(int tci) {
		TCI.setShort(view(), 0, (short) tci);
	}

	/**
	 * Returns the Priority Code Point field (3 bits).
	 * 
	 * <p>
	 * PCP values map to IEEE 802.1p priority levels:
	 * </p>
	 * <ul>
	 * <li>0 - Best effort (default)</li>
	 * <li>1 - Background</li>
	 * <li>2 - Excellent effort</li>
	 * <li>3 - Critical applications</li>
	 * <li>4 - Video, &lt; 100ms latency</li>
	 * <li>5 - Voice, &lt; 10ms latency</li>
	 * <li>6 - Internetwork control</li>
	 * <li>7 - Network control</li>
	 * </ul>
	 *
	 * @return the priority value (0-7)
	 */
	public int pcp() {
		return (tci() & PCP_MASK) >>> PCP_SHIFT;
	}

	/**
	 * Sets the Priority Code Point field.
	 *
	 * @param pcp the priority value (0-7)
	 */
	public void setPcp(int pcp) {
		int tci = tci();
		tci = (tci & ~PCP_MASK) | ((pcp << PCP_SHIFT) & PCP_MASK);
		setTci(tci);
	}

	/**
	 * Returns the Drop Eligible Indicator field (1 bit).
	 * 
	 * <p>
	 * Formerly called CFI (Canonical Format Indicator). When set, indicates
	 * the frame may be dropped during congestion.
	 * </p>
	 *
	 * @return true if drop eligible
	 */
	public boolean dei() {
		return (tci() & DEI_MASK) != 0;
	}

	/**
	 * Sets the Drop Eligible Indicator field.
	 *
	 * @param dei true to mark as drop eligible
	 */
	public void setDei(boolean dei) {
		int tci = tci();
		if (dei) {
			tci |= DEI_MASK;
		} else {
			tci &= ~DEI_MASK;
		}
		setTci(tci);
	}

	/**
	 * Returns the VLAN Identifier field (12 bits).
	 *
	 * @return the VLAN ID (0-4095)
	 * @see #VID_PRIORITY
	 * @see #VID_DEFAULT
	 * @see #VID_RESERVED
	 */
	public int vid() {
		return tci() & VID_MASK;
	}

	/**
	 * Sets the VLAN Identifier field.
	 *
	 * @param vid the VLAN ID (0-4095)
	 */
	public void setVid(int vid) {
		int tci = tci();
		tci = (tci & ~VID_MASK) | (vid & VID_MASK);
		setTci(tci);
	}

	/**
	 * Returns the encapsulated protocol EtherType (16 bits).
	 * 
	 * <p>
	 * This is the EtherType of the payload following the VLAN tag.
	 * May be another VLAN tag (QinQ) or an upper-layer protocol.
	 * </p>
	 *
	 * @return the EtherType value
	 * @see EtherTypeResolver
	 */
	public int etherType() {
		return ETHERTYPE.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the encapsulated protocol EtherType.
	 *
	 * @param etherType the EtherType value
	 */
	public void setEtherType(int etherType) {
		ETHERTYPE.setShort(view(), 0, (short) etherType);
	}

	/**
	 * Checks if this is a priority-tagged frame.
	 * 
	 * <p>
	 * Priority-tagged frames have VID 0 and carry only priority information
	 * without VLAN membership.
	 * </p>
	 *
	 * @return true if VID is 0
	 */
	public boolean isPriorityTagged() {
		return vid() == VID_PRIORITY;
	}

	/**
	 * Checks if this VLAN tag is followed by another VLAN tag (QinQ).
	 *
	 * @return true if etherType indicates another VLAN tag
	 */
	public boolean isStacked() {
		int type = etherType();
		return type == TPID_8021Q || type == TPID_8021AD || type == TPID_QINQ_LEGACY;
	}

	/**
	 * Returns a human-readable priority class name.
	 *
	 * @return the priority class description
	 */
	public String pcpToString() {
		return switch (pcp()) {
			case 0 -> "Best Effort";
			case 1 -> "Background";
			case 2 -> "Excellent Effort";
			case 3 -> "Critical Applications";
			case 4 -> "Video";
			case 5 -> "Voice";
			case 6 -> "Internetwork Control";
			case 7 -> "Network Control";
			default -> "Unknown";
		};
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("802.1Q Virtual LAN", ID, off, HEADER_LENGTH, h -> {
			h.summaryf("VID=%d PCP=%d %s",
					vid(), pcp(),
					EtherTypeResolver.resolveAbbrOrHex(etherType()));

			h.expandField("TCI", tci(),
					String.format("PCP=%d, DEI=%d, VID=%d", pcp(), dei() ? 1 : 0, vid()),
					shortAt(off), f -> {
						f.field("Priority", pcp(), pcpToString(), bitsAt(off * 8L, 3));
						f.field("DEI", dei() ? 1 : 0, dei() ? "Eligible" : "Not eligible", bitsAt(off * 8L + 3, 1));
						f.field("VLAN ID", vid(), bitsAt(off * 8L + 4, 12));
					});

			h.fieldHex("Type", etherType(), 4,
					EtherTypeResolver.resolve(etherType()),
					shortAt(off + 2));
		});
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return toDetailString();
	}
}