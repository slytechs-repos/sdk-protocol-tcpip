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
package com.slytechs.sdk.protocol.tcpip.ethernet;

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.util.Iterator;
import java.util.NoSuchElementException;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.detail.render.TextRenderer;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryBuffer;
import com.slytechs.sdk.protocol.core.HeaderExtension;
import com.slytechs.sdk.protocol.core.HeaderExtensions;
import com.slytechs.sdk.protocol.core.ProtocolId;

/**
 * IEEE 802.3 Ethernet extensions container with zero-allocation inner classes.
 * 
 * <p>
 * Provides access to LLC (Logical Link Control) and SNAP (Sub-Network Access
 * Protocol) headers that follow the 802.3 Ethernet frame header.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class Eth8023Extensions extends BoundView
		implements HeaderExtensions<Eth8023Extensions.Eth8023Extension>, Detailable,
		Iterable<Eth8023Extensions.Eth8023Extension> {

	public static final int LLC = 1;
	public static final int SNAP = 2;

	public static final int DSAP_SNAP = 0xAA;
	public static final int SSAP_SNAP = 0xAA;
	public static final int DSAP_STP = 0x42;
	public static final int SSAP_STP = 0x42;
	public static final int DSAP_IPX = 0xE0;
	public static final int SSAP_IPX = 0xE0;
	public static final int DSAP_NETBIOS = 0xF0;
	public static final int SSAP_NETBIOS = 0xF0;
	public static final int DSAP_ISO = 0xFE;
	public static final int SSAP_ISO = 0xFE;
	public static final int DSAP_GLOBAL = 0xFF;

	public static final int CONTROL_UI = 0x03;
	public static final int CONTROL_XID = 0xAF;
	public static final int CONTROL_TEST = 0xE3;

	public static final int OUI_CISCO = 0x00000C;
	public static final int OUI_APPLE = 0x080007;
	public static final int OUI_RFC1042 = 0x000000;

	public static final int LLC_HEADER_LENGTH = 3;
	public static final int LLC_HEADER_LENGTH_EXTENDED = 4;
	public static final int SNAP_HEADER_LENGTH = 5;

	private static final int ETH_HEADER_LENGTH = 14;
	private static final int MAX_EXTENSIONS = 2;

	private long bitmask;

	private final MemoryBuffer buffer = new MemoryBuffer();
	private final int[] chain = new int[MAX_EXTENSIONS];
	private int chainLength;
	private boolean parsed;

	public class Eth8023Extension implements HeaderExtension {
		protected final int id;
		protected int offset;
		protected int length;

		protected Eth8023Extension(int id) {
			this.id = id;
			register(this);
		}

		@Override
		public final int extensionId() {
			return id;
		}

		@Override
		public final int extensionOffset() {
			return offset;
		}

		@Override
		public final int extensionLength() {
			return length;
		}

		@Override
		public final boolean isPresent() {
			ensureParsed();
			return (bitmask & (1L << id)) != 0;
		}

		@Override
		public String extensionName() {
			return Eth8023Extensions.extensionName(id);
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = ETH_HEADER_LENGTH + offset;
			h.field("Data", "[" + length + " bytes]", bits(hdrOff, length));
		}
	}

	public final class Llc extends Eth8023Extension {
		public static final int HEADER_ID = ProtocolId.LLC;

		private Llc() {
			super(LLC);
		}

		public int dsap() {
			return isPresent() ? buffer.get(offset) & 0xFF : -1;
		}

		public int ssap() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public boolean dsapIndividual() {
			return isPresent() && (buffer.get(offset) & 0x01) == 0;
		}

		public boolean dsapGroup() {
			return isPresent() && (buffer.get(offset) & 0x01) != 0;
		}

		public boolean ssapCommand() {
			return isPresent() && (buffer.get(offset + 1) & 0x01) == 0;
		}

		public boolean ssapResponse() {
			return isPresent() && (buffer.get(offset + 1) & 0x01) != 0;
		}

		public int control() {
			return isPresent() ? buffer.get(offset + 2) & 0xFF : -1;
		}

		public int controlExtended() {
			if (!isPresent() || length < 4)
				return -1;
			return buffer.getShort(offset + 2) & 0xFFFF;
		}

		public boolean isUnnumbered() {
			return isPresent() && (control() & 0x03) == 0x03;
		}

		public boolean isSupervisory() {
			return isPresent() && (control() & 0x03) == 0x01;
		}

		public boolean isInformation() {
			return isPresent() && (control() & 0x01) == 0x00;
		}

		public boolean isSnap() {
			return isPresent() && dsap() == DSAP_SNAP && ssap() == SSAP_SNAP;
		}

		public boolean isStp() {
			return isPresent() && dsap() == DSAP_STP && ssap() == SSAP_STP;
		}

		public boolean isIpx() {
			return isPresent() && dsap() == DSAP_IPX && ssap() == SSAP_IPX;
		}

		public boolean isNetbios() {
			return isPresent() && dsap() == DSAP_NETBIOS && ssap() == SSAP_NETBIOS;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = ETH_HEADER_LENGTH + offset;
			h.expandField("DSAP", dsap(), dsapName(dsap()), byteAt(hdrOff), f -> {
				f.field("SAP", dsap() & 0xFE, bitsAt(hdrOff * 8L, 7));
				f.field("I/G", dsapGroup() ? 1 : 0, dsapGroup() ? "Group" : "Individual", bitsAt(hdrOff * 8L + 7, 1));
			});
			h.expandField("SSAP", ssap(), ssapName(ssap()), byteAt(hdrOff + 1), f -> {
				f.field("SAP", ssap() & 0xFE, bitsAt((hdrOff + 1) * 8L, 7));
				f.field("C/R", ssapResponse() ? 1 : 0, ssapResponse() ? "Response" : "Command", bitsAt((hdrOff + 1) * 8L
						+ 7, 1));
			});
			String ctrlType = isUnnumbered() ? "Unnumbered" : (isSupervisory() ? "Supervisory" : "Information");
			h.field("Control", control(), ctrlType + " (" + controlName(control()) + ")", byteAt(hdrOff + 2));
		}
	}

	public final class Snap extends Eth8023Extension {
		public static final int HEADER_ID = ProtocolId.SNAP;

		private Snap() {
			super(SNAP);
		}

		public int oui() {
			if (!isPresent())
				return -1;
			return ((buffer.get(offset) & 0xFF) << 16) |
					((buffer.get(offset + 1) & 0xFF) << 8) |
					(buffer.get(offset + 2) & 0xFF);
		}

		public int protocolId() {
			return isPresent() ? buffer.getShort(offset + 3) & 0xFFFF : -1;
		}

		public boolean isRfc1042() {
			return isPresent() && oui() == OUI_RFC1042;
		}

		public boolean isCisco() {
			return isPresent() && oui() == OUI_CISCO;
		}

		public boolean isApple() {
			return isPresent() && oui() == OUI_APPLE;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = ETH_HEADER_LENGTH + offset;
			h.fieldHex("OUI", oui(), 6, bits(hdrOff, 3));
			String ouiName = ouiName(oui());
			if (ouiName != null) {
				h.field("Organization", ouiName);
			}
			h.fieldHex("Protocol HEADER_ID", protocolId(), 4, shortAt(hdrOff + 3));
			String protoName = protocolName(protocolId());
			if (protoName != null) {
				h.field("Protocol", protoName);
			}
		}
	}

	public static String protocolName(int protocolId) {
		return EtherTypeResolver.resolve(protocolId);
	}

	public static String protocolNameAbbr(int protocolId) {
		return EtherTypeResolver.resolveAbbr(protocolId);
	}

	public static String ouiName(int oui) {
		return OuiResolver.resolve(oui);
	}

	private final Eth8023Extension[] registry = new Eth8023Extension[8];

	private final Llc llc = new Llc();
	private final Snap snap = new Snap();

	Eth8023Extensions() {}

	private void register(Eth8023Extension extension) {
		registry[extension.id] = extension;
	}

	@Override
	public void onBind() {
		buffer.bind(this);
	}

	@Override
	public void onUnbind() {
		parsed = false;
		buffer.unbind();
	}

	private void setPresent(int id) {
		bitmask |= (1L << id);
	}

	public boolean hasLlcExtension() {
		return llc.isPresent();
	}

	public boolean hasSnapExtension() {
		return snap.isPresent();
	}

	public Llc llcExtension() {
		return llc;
	}

	public Snap snapExtension() {
		return snap;
	}

	@Override
	public boolean hasExtension(int id) {
		ensureParsed();
		return (bitmask & (1L << id)) != 0;
	}

	@Override
	public Eth8023Extension extension(int id) {
		ensureParsed();
		return registry[id];
	}

	@Override
	public int count() {
		ensureParsed();
		return chainLength;
	}

	@Override
	public long totalLength() {
		ensureParsed();
		long total = 0;
		for (int i = 0; i < chainLength; i++) {
			Eth8023Extension ext = registry[chain[i]];
			if (ext != null) {
				total += ext.length;
			}
		}
		return total;
	}

	@Override
	public Iterator<Eth8023Extension> iterator() {
		ensureParsed();
		return new ExtensionIterator();
	}

	private class ExtensionIterator implements Iterator<Eth8023Extension> {
		private int index = 0;

		@Override
		public boolean hasNext() {
			return index < chainLength;
		}

		@Override
		public Eth8023Extension next() {
			if (!hasNext())
				throw new NoSuchElementException();
			return registry[chain[index++]];
		}
	}

	private void ensureParsed() {
		if (!parsed) {
			parse();
		}
	}

	private void parse() {
		bitmask = 0;
		chainLength = 0;

		long end = buffer.limit();
		if (end < LLC_HEADER_LENGTH) {
			parsed = true;
			return;
		}

		int dsap = buffer.get(0) & 0xFF;
		int ssap = buffer.get(1) & 0xFF;
		int control = buffer.get(2) & 0xFF;

		int llcLen = isExtendedControl(control) && end >= LLC_HEADER_LENGTH_EXTENDED
				? LLC_HEADER_LENGTH_EXTENDED
				: LLC_HEADER_LENGTH;

		setPresent(LLC);
		chain[chainLength++] = LLC;
		llc.offset = 0;
		llc.length = llcLen;

		if (dsap == DSAP_SNAP && ssap == SSAP_SNAP && end >= llcLen + SNAP_HEADER_LENGTH) {
			setPresent(SNAP);
			chain[chainLength++] = SNAP;
			snap.offset = llcLen;
			snap.length = SNAP_HEADER_LENGTH;
		}

		parsed = true;
	}

	private static boolean isExtendedControl(int control) {
		return (control & 0x03) != 0x03;
	}

	public static String extensionName(int id) {
		return switch (id) {
		case LLC -> "LLC";
		case SNAP -> "SNAP";
		default -> "Unknown (" + id + ")";
		};
	}

	public static String dsapName(int dsap) {
		int sap = dsap & 0xFE;
		return switch (sap) {
		case 0x00 -> "Null";
		case 0x02 -> "Individual LLC Sublayer Management";
		case 0x06 -> "IP (DOD)";
		case 0x42 -> "STP";
		case 0x4E -> "RS-511";
		case 0x5E -> "ISI IP";
		case 0x7E -> "X.25 PLP";
		case 0x80 -> "XNS";
		case 0x8E -> "PROWAY";
		case 0xAA -> "SNAP";
		case 0xBC -> "Banyan Vines";
		case 0xE0 -> "IPX";
		case 0xF0 -> "NetBIOS";
		case 0xF4 -> "IBM LAN Management";
		case 0xF8 -> "IBM RPL";
		case 0xFC -> "IBM Discovery";
		case 0xFE -> "ISO";
		default -> String.format("0x%02X", dsap);
		};
	}

	public static String controlName(int control) {
		if ((control & 0x03) == 0x03) {
			return switch (control & 0xEF) {
			case 0x03 -> "UI";
			case 0x0F -> "DM";
			case 0x43 -> "DISC";
			case 0x63 -> "UA";
			case 0x6F -> "SABME";
			case 0x87 -> "FRMR";
			case 0xAF -> "XID";
			case 0xE3 -> "TEST";
			default -> String.format("0x%02X", control);
			};
		} else if ((control & 0x01) == 0x01) {
			int s = (control >> 2) & 0x03;
			return switch (s) {
			case 0 -> "RR";
			case 1 -> "RNR";
			case 2 -> "REJ";
			default -> "S" + s;
			};
		} else {
			return "I";
		}
	}

	public static String ssapName(int ssap) {
		return dsapName(ssap & 0xFE);
	}

	@Override
	public void buildDetail(DetailBuilder b) {
		ensureParsed();
		if (chainLength == 0)
			return;

		for (Eth8023Extension ext : this) {
			int hdrOff = ETH_HEADER_LENGTH + ext.offset;
			b.header("802.3 Extension - " + ext.extensionName(), "802.2", ext.id, hdrOff, ext.length, ext::buildDetail);
		}
	}

	@Override
	public String toString() {
		return new TextRenderer().render(getDetail());
	}
}