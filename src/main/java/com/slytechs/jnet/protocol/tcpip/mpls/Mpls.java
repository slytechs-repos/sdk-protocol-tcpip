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
package com.slytechs.jnet.protocol.tcpip.mpls;

import static com.slytechs.jnet.core.api.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.detail.DetailBuilder;
import com.slytechs.jnet.core.api.detail.Detailable;
import com.slytechs.jnet.core.api.memory.MemoryHandle.IntHandle;
import com.slytechs.jnet.protocol.api.FixedHeader;
import com.slytechs.jnet.protocol.api.ProtocolId;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Multi-Protocol Label Switching (MPLS) label header as defined in RFC 3032.
 * 
 * <p>
 * MPLS is a packet-forwarding technology that uses labels to make data
 * forwarding decisions. MPLS labels are inserted between the Layer 2 header
 * (e.g., Ethernet) and the Layer 3 header (e.g., IP). Multiple labels can be
 * stacked, with the Bottom of Stack (S) bit indicating the last label.
 * </p>
 * 
 * <h2>Header Format</h2>
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Label                 | TC  |S|      TTL      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Fields</h2>
 * <ul>
 * <li><b>Label</b> (20 bits) - Label value used for forwarding decisions</li>
 * <li><b>TC</b> (3 bits) - Traffic Class, formerly EXP (Experimental)</li>
 * <li><b>S</b> (1 bit) - Bottom of Stack indicator (1 = last label)</li>
 * <li><b>TTL</b> (8 bits) - Time To Live, decremented at each hop</li>
 * </ul>
 * 
 * <h2>Reserved Labels (0-15)</h2>
 * <ul>
 * <li>0 - IPv4 Explicit NULL</li>
 * <li>1 - Router Alert</li>
 * <li>2 - IPv6 Explicit NULL</li>
 * <li>3 - Implicit NULL (never appears on wire)</li>
 * <li>4-6 - Unassigned</li>
 * <li>7 - Entropy Label Indicator (ELI)</li>
 * <li>8-12 - Unassigned</li>
 * <li>13 - Generic Associated Channel (GAL)</li>
 * <li>14 - OAM Alert</li>
 * <li>15 - Extension Label (XL)</li>
 * </ul>
 * 
 * <h2>Label Stacking</h2>
 * <p>
 * Multiple MPLS labels can be stacked. Each label is parsed as a separate
 * Mpls header. Use {@link #isBottomOfStack()} to determine if this is the
 * last label before the payload.
 * </p>
 * 
 * {@snippet :
 * Mpls mpls = packet.getHeader(new Mpls());
 * 
 * System.out.println("Label: " + mpls.label());
 * System.out.println("TC: " + mpls.tc());
 * System.out.println("TTL: " + mpls.ttl());
 * 
 * if (mpls.isBottomOfStack()) {
 *     System.out.println("Last label in stack");
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see <a href="https://tools.ietf.org/html/rfc3032">RFC 3032 - MPLS Label Stack Encoding</a>
 */
public class Mpls extends FixedHeader implements Detailable {

	/** Protocol HEADER_ID for MPLS. */
	public static final int HEADER_ID = ProtocolId.MPLS;

	/** MPLS label header length in bytes. */
	public static final int HEADER_LENGTH = 4;

	/** IPv4 Explicit NULL label - indicates IPv4 payload, pop label. */
	public static final int LABEL_IPV4_EXPLICIT_NULL = 0;

	/** Router Alert label - deliver to local control plane. */
	public static final int LABEL_ROUTER_ALERT = 1;

	/** IPv6 Explicit NULL label - indicates IPv6 payload, pop label. */
	public static final int LABEL_IPV6_EXPLICIT_NULL = 2;

	/** Implicit NULL label - signaled but never appears on wire. */
	public static final int LABEL_IMPLICIT_NULL = 3;

	/** Entropy Label Indicator - next label is entropy label. */
	public static final int LABEL_ELI = 7;

	/** Generic Associated Channel label - OAM/control channel. */
	public static final int LABEL_GAL = 13;

	/** OAM Alert label. */
	public static final int LABEL_OAM_ALERT = 14;

	/** Extension Label - extended label space follows. */
	public static final int LABEL_EXTENSION = 15;

	/** Minimum reserved label value. */
	public static final int LABEL_RESERVED_MIN = 0;

	/** Maximum reserved label value. */
	public static final int LABEL_RESERVED_MAX = 15;

	/** Maximum label value (20 bits). */
	public static final int LABEL_MAX = 0xFFFFF;

	/** MPLS header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U32_BE.withName("hdr_label_tc_s_ttl")
	);

	private static final IntHandle LABEL_ENTRY = new IntHandle(LAYOUT, "hdr_label_tc_s_ttl");

	private static final int LABEL_MASK = 0xFFFFF000;
	private static final int LABEL_SHIFT = 12;
	private static final int TC_MASK = 0x00000E00;
	private static final int TC_SHIFT = 9;
	private static final int S_MASK = 0x00000100;
	private static final int S_SHIFT = 8;
	private static final int TTL_MASK = 0x000000FF;

	/**
	 * Constructs a new MPLS header.
	 */
	public Mpls() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the raw 32-bit label stack entry.
	 *
	 * @return the complete label stack entry
	 */
	public int labelEntry() {
		return LABEL_ENTRY.getInt(view());
	}

	/**
	 * Sets the raw 32-bit label stack entry.
	 *
	 * @param entry the complete label stack entry
	 */
	public void setLabelEntry(int entry) {
		LABEL_ENTRY.setInt(view(), 0, entry);
	}

	/**
	 * Returns the label field (20 bits).
	 * 
	 * <p>
	 * The label value is used by MPLS routers to make forwarding decisions.
	 * Labels 0-15 are reserved for special purposes.
	 * </p>
	 *
	 * @return the label value (0-1048575)
	 * @see #isReservedLabel()
	 */
	public int label() {
		return (labelEntry() & LABEL_MASK) >>> LABEL_SHIFT;
	}

	/**
	 * Sets the label field.
	 *
	 * @param label the label value (0-1048575)
	 */
	public void setLabel(int label) {
		int entry = labelEntry();
		entry = (entry & ~LABEL_MASK) | ((label << LABEL_SHIFT) & LABEL_MASK);
		setLabelEntry(entry);
	}

	/**
	 * Returns the Traffic Class field (3 bits).
	 * 
	 * <p>
	 * Formerly called EXP (Experimental). Used for QoS and ECN signaling.
	 * The TC field typically maps to IP DSCP/ECN values.
	 * </p>
	 *
	 * @return the traffic class value (0-7)
	 */
	public int tc() {
		return (labelEntry() & TC_MASK) >>> TC_SHIFT;
	}

	/**
	 * Sets the Traffic Class field.
	 *
	 * @param tc the traffic class value (0-7)
	 */
	public void setTc(int tc) {
		int entry = labelEntry();
		entry = (entry & ~TC_MASK) | ((tc << TC_SHIFT) & TC_MASK);
		setLabelEntry(entry);
	}

	/**
	 * Returns the Experimental field (3 bits).
	 * 
	 * <p>
	 * Legacy name for the Traffic Class field.
	 * </p>
	 *
	 * @return the experimental/TC value (0-7)
	 * @see #tc()
	 */
	public int exp() {
		return tc();
	}

	/**
	 * Sets the Experimental field.
	 *
	 * @param exp the experimental/TC value (0-7)
	 * @see #setTc(int)
	 */
	public void setExp(int exp) {
		setTc(exp);
	}

	/**
	 * Returns the Bottom of Stack bit (1 bit).
	 *
	 * @return 1 if this is the bottom label, 0 otherwise
	 */
	public int s() {
		return (labelEntry() & S_MASK) >>> S_SHIFT;
	}

	/**
	 * Sets the Bottom of Stack bit.
	 *
	 * @param s 1 for bottom of stack, 0 otherwise
	 */
	public void setS(int s) {
		int entry = labelEntry();
		if (s != 0) {
			entry |= S_MASK;
		} else {
			entry &= ~S_MASK;
		}
		setLabelEntry(entry);
	}

	/**
	 * Checks if this is the bottom label in the stack.
	 * 
	 * <p>
	 * When the S bit is set, this is the last MPLS label before the payload
	 * (typically an IP packet).
	 * </p>
	 *
	 * @return true if this is the last label in the stack
	 */
	public boolean isBottomOfStack() {
		return (labelEntry() & S_MASK) != 0;
	}

	/**
	 * Sets the Bottom of Stack flag.
	 *
	 * @param bottom true to mark as bottom of stack
	 */
	public void setBottomOfStack(boolean bottom) {
		setS(bottom ? 1 : 0);
	}

	/**
	 * Returns the Time To Live field (8 bits).
	 * 
	 * <p>
	 * Decremented by each LSR (Label Switching Router). The packet is
	 * discarded when TTL reaches zero, preventing routing loops.
	 * </p>
	 *
	 * @return the TTL value (0-255)
	 */
	public int ttl() {
		return labelEntry() & TTL_MASK;
	}

	/**
	 * Sets the Time To Live field.
	 *
	 * @param ttl the TTL value (0-255)
	 */
	public void setTtl(int ttl) {
		int entry = labelEntry();
		entry = (entry & ~TTL_MASK) | (ttl & TTL_MASK);
		setLabelEntry(entry);
	}

	/**
	 * Checks if this label is a reserved label (0-15).
	 * 
	 * <p>
	 * Reserved labels have special meanings defined by IANA and should
	 * not be used for normal LSP signaling.
	 * </p>
	 *
	 * @return true if label value is 0-15
	 */
	public boolean isReservedLabel() {
		return label() <= LABEL_RESERVED_MAX;
	}

	/**
	 * Checks if this is an Explicit NULL label (IPv4 or IPv6).
	 * 
	 * <p>
	 * Explicit NULL labels indicate the payload type and signal that the
	 * label should be popped before forwarding.
	 * </p>
	 *
	 * @return true if label is 0 (IPv4) or 2 (IPv6)
	 */
	public boolean isExplicitNull() {
		int lbl = label();
		return lbl == LABEL_IPV4_EXPLICIT_NULL || lbl == LABEL_IPV6_EXPLICIT_NULL;
	}

	/**
	 * Checks if this is a Router Alert label.
	 * 
	 * <p>
	 * Router Alert labels cause the packet to be delivered to the local
	 * control plane for processing.
	 * </p>
	 *
	 * @return true if label is 1
	 */
	public boolean isRouterAlert() {
		return label() == LABEL_ROUTER_ALERT;
	}

	/**
	 * Returns a human-readable description of reserved labels.
	 *
	 * @return description of the label, or null if not reserved
	 */
	public String labelToString() {
		return switch (label()) {
			case LABEL_IPV4_EXPLICIT_NULL -> "IPv4 Explicit NULL";
			case LABEL_ROUTER_ALERT -> "Router Alert";
			case LABEL_IPV6_EXPLICIT_NULL -> "IPv6 Explicit NULL";
			case LABEL_IMPLICIT_NULL -> "Implicit NULL";
			case LABEL_ELI -> "Entropy Label Indicator";
			case LABEL_GAL -> "Generic Associated Channel";
			case LABEL_OAM_ALERT -> "OAM Alert";
			case LABEL_EXTENSION -> "Extension Label";
			default -> label() <= LABEL_RESERVED_MAX ? "Reserved" : null;
		};
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();
		String labelDesc = labelToString();

		b.header("Multi-Protocol Label Switching", "MPLS", HEADER_ID, off, HEADER_LENGTH, h -> {
			h.summaryf("Label=%d TC=%d S=%d TTL=%d%s",
					label(), tc(), s(), ttl(),
					labelDesc != null ? " [" + labelDesc + "]" : "");

			h.expandField("Label Stack Entry", labelEntry(),
					String.format("Label=%d, TC=%d, S=%d, TTL=%d", label(), tc(), s(), ttl()),
					intAt(off), f -> {
						if (labelDesc != null) {
							f.field("Label", label(), labelDesc, bitsAt(off * 8L, 20));
						} else {
							f.field("Label", label(), bitsAt(off * 8L, 20));
						}
						f.field("Traffic Class", tc(), bitsAt(off * 8L + 20, 3));
						f.field("Bottom of Stack", s(), isBottomOfStack() ? "Yes" : "No", bitsAt(off * 8L + 23, 1));
						f.field("TTL", ttl(), bitsAt(off * 8L + 24, 8));
					});
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