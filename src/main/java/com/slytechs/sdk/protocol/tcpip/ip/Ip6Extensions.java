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
package com.slytechs.sdk.protocol.tcpip.ip;

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.util.Iterator;
import java.util.NoSuchElementException;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.detail.render.TextRenderer;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryBuffer;
import com.slytechs.sdk.protocol.core.header.HeaderExtension;
import com.slytechs.sdk.protocol.core.header.HeaderExtensions;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * IPv6 extension headers container with zero-allocation inner extension
 * classes.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class Ip6Extensions extends BoundView
		implements HeaderExtensions<Ip6Extensions.Ip6Extension>, Detailable,
		Iterable<Ip6Extensions.Ip6Extension> {

	public static final int HOP_BY_HOP = 0;
	public static final int HOPBYHOP = 0;
	public static final int ROUTING = 43;
	public static final int FRAGMENT = 44;
	public static final int ESP = 50;
	public static final int ENCAPSULATING_SECURITY_PAYLOAD = 50;
	public static final int AH = 51;
	public static final int AUTHENTICATION = 51;
	public static final int DESTINATION = 60;
	public static final int DESTINATION_OPTIONS = 60;
	public static final int MOBILITY = 135;
	public static final int HIP = 139;
	public static final int HOST_IDENTITY_PROTOCOL = 139;
	public static final int SHIM6 = 140;
	public static final int EXPERIMENTAL_253 = 253;
	public static final int EXPERIMENTAL_254 = 254;

	public static final int TCP = 6;
	public static final int UDP = 17;
	public static final int ICMPV6 = 58;
	public static final int IPV6_IN_IPV6 = 41;
	public static final int NO_NEXT_HEADER = 59;

	public static final int MIN_EXTENSION_LENGTH = 8;
	public static final int FRAGMENT_LENGTH = 8;

	public static final int ROUTING_TYPE_SOURCE = 0;
	public static final int ROUTING_TYPE_NIMROD = 1;
	public static final int ROUTING_TYPE_MOBILE_IPV6 = 2;
	public static final int ROUTING_TYPE_RPL = 3;
	public static final int ROUTING_TYPE_SEGMENT = 4;

	public static final int MOBILITY_BRR = 0;
	public static final int MOBILITY_HOTI = 1;
	public static final int MOBILITY_COTI = 2;
	public static final int MOBILITY_HOT = 3;
	public static final int MOBILITY_COT = 4;
	public static final int MOBILITY_BU = 5;
	public static final int MOBILITY_BA = 6;
	public static final int MOBILITY_BE = 7;
	public static final int MOBILITY_FBU = 8;
	public static final int MOBILITY_FBACK = 9;
	public static final int MOBILITY_FNA = 10;

	private static final int IP6_HEADER_LENGTH = 40;
	private static final int MAX_EXTENSIONS = 16;

	private long bitmask0;
	private long bitmask1;
	private long bitmask2;
	private long bitmask3;

	private final int[] chain = new int[MAX_EXTENSIONS];
	private int chainLength;
	private int finalProtocol;
	private boolean parsed;

	private final MemoryBuffer buffer = new MemoryBuffer();
	private Ip6 parent;

	public class Ip6Extension implements HeaderExtension {
		protected final int id;
		protected int offset;
		protected int length;

		protected Ip6Extension(int id) {
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
			return switch (id >> 6) {
			case 0 -> (bitmask0 & (1L << id)) != 0;
			case 1 -> (bitmask1 & (1L << (id - 64))) != 0;
			case 2 -> (bitmask2 & (1L << (id - 128))) != 0;
			case 3 -> (bitmask3 & (1L << (id - 192))) != 0;
			default -> false;
			};
		}

		public int nextHeader() {
			return isPresent() ? buffer.get(offset) & 0xFF : -1;
		}

		@Override
		public String extensionName() {
			return Ip6Extensions.extensionName(id);
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", buffer.get(offset + 1) & 0xFF, byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Data", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	public final class HopByHop extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_HOPOPT;

		private HopByHop() {
			super(HOP_BY_HOP);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int headerLengthBytes() {
			int len = headerLength();
			return len >= 0 ? (len + 1) * 8 : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), headerLengthBytes() + " bytes", byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Options", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	public final class Routing extends Ip6Extension {
		private Routing() {
			super(ROUTING);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int headerLengthBytes() {
			int len = headerLength();
			return len >= 0 ? (len + 1) * 8 : -1;
		}

		public int routingType() {
			return isPresent() ? buffer.get(offset + 2) & 0xFF : -1;
		}

		public int segmentsLeft() {
			return isPresent() ? buffer.get(offset + 3) & 0xFF : -1;
		}

		public int addressCount() {
			return isPresent() ? (length - 8) / 16 : 0;
		}

		public byte[] address(int index) {
			if (!isPresent() || index < 0 || index >= addressCount())
				return null;
			byte[] addr = new byte[16];
			for (int i = 0; i < 16; i++) {
				addr[i] = buffer.get(offset + 8 + index * 16 + i);
			}
			return addr;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), headerLengthBytes() + " bytes", byteAt(hdrOff + 1));
			h.field("Routing Type", routingType(), routingTypeName(routingType()), byteAt(hdrOff + 2));
			h.field("Segments Left", segmentsLeft(), byteAt(hdrOff + 3));
			h.field("Reserved", buffer.getInt(offset + 4), intAt(hdrOff + 4));

			for (int i = 0; i < addressCount(); i++) {
				int idx = i;
				h.field("Address " + i, formatIp6(address(idx)), bits(hdrOff + 8 + i * 16, 16));
			}
		}
	}

	public final class Fragment extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_FRAG;

		private Fragment() {
			super(FRAGMENT);
		}

		public int reserved() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int fragmentOffset() {
			if (!isPresent())
				return -1;
			int value = buffer.getShort(offset + 2) & 0xFFFF;
			return (value >> 3) & 0x1FFF;
		}

		public int fragmentOffsetBytes() {
			int off = fragmentOffset();
			return off < 0 ? -1 : off * 8;
		}

		public int flags() {
			return isPresent() ? buffer.get(offset + 3) & 0x07 : -1;
		}

		public boolean moreFragments() {
			return isPresent() && (buffer.get(offset + 3) & 0x01) != 0;
		}

		public int identification() {
			return isPresent() ? buffer.getInt(offset + 4) : -1;
		}

		public boolean isFirst() {
			return isPresent() && fragmentOffset() == 0;
		}

		public boolean isLast() {
			return isPresent() && !moreFragments();
		}

		public boolean isMiddle() {
			return isPresent() && fragmentOffset() > 0 && moreFragments();
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Reserved", reserved(), byteAt(hdrOff + 1));
			h.expandField("Offset/Flags", buffer.getShort(offset + 2) & 0xFFFF,
					String.format("Offset=%d, M=%d", fragmentOffset(), moreFragments() ? 1 : 0),
					shortAt(hdrOff + 2), f -> {
						f.field("Fragment Offset", fragmentOffset(), fragmentOffsetBytes() + " bytes", bitsAt((hdrOff
								+ 2) * 8L, 13));
						f.field("Reserved", (buffer.getShort(offset + 2) >> 1) & 0x03, bitsAt((hdrOff + 2) * 8L + 13, 2));
						f.field("More Fragments", moreFragments() ? 1 : 0, moreFragments() ? "Yes" : "No", bitsAt(
								(hdrOff + 2) * 8L + 15, 1));
					});
			h.fieldHex("Identification", identification(), 8, intAt(hdrOff + 4));
		}
	}

	public final class Destination extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_DSTOPT;

		private Destination() {
			super(DESTINATION);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int headerLengthBytes() {
			int len = headerLength();
			return len >= 0 ? (len + 1) * 8 : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), headerLengthBytes() + " bytes", byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Options", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	public final class Authentication extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_AUTH;

		private Authentication() {
			super(AH);
		}

		public int payloadLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int headerLengthBytes() {
			int len = payloadLength();
			return len >= 0 ? (len + 2) * 4 : -1;
		}

		public int reserved() {
			return isPresent() ? buffer.getShort(offset + 2) & 0xFFFF : -1;
		}

		public int spi() {
			return isPresent() ? buffer.getInt(offset + 4) : -1;
		}

		public int sequenceNumber() {
			return isPresent() ? buffer.getInt(offset + 8) : -1;
		}

		public int icvLength() {
			if (!isPresent())
				return 0;
			return headerLengthBytes() - 12;
		}

		public int icvOffset() {
			return isPresent() ? offset + 12 : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Payload Length", payloadLength(), headerLengthBytes() + " bytes", byteAt(hdrOff + 1));
			h.field("Reserved", reserved(), shortAt(hdrOff + 2));
			h.fieldHex("SPI", spi(), 8, intAt(hdrOff + 4));
			h.field("Sequence Number", sequenceNumber() & 0xFFFFFFFFL, intAt(hdrOff + 8));
			int icvLen = icvLength();
			if (icvLen > 0) {
				h.field("ICV", "[" + icvLen + " bytes]", bits(hdrOff + 12, icvLen));
			}
		}
	}

	public final class Esp extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_ESP;

		private Esp() {
			super(ESP);
		}

		public int spi() {
			return isPresent() ? buffer.getInt(offset) : -1;
		}

		public int sequenceNumber() {
			return isPresent() ? buffer.getInt(offset + 4) : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.fieldHex("SPI", spi(), 8, intAt(hdrOff));
			h.field("Sequence Number", sequenceNumber() & 0xFFFFFFFFL, intAt(hdrOff + 4));
			if (length > 8) {
				h.field("Encrypted Data", "[" + (length - 8) + " bytes]", bits(hdrOff + 8, length - 8));
			}
		}
	}

	public final class Mobility extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_MOBILITY;

		private Mobility() {
			super(MOBILITY);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		public int mhType() {
			return isPresent() ? buffer.get(offset + 2) & 0xFF : -1;
		}

		public int reserved() {
			return isPresent() ? buffer.get(offset + 3) & 0xFF : -1;
		}

		public int checksum() {
			return isPresent() ? buffer.getShort(offset + 4) & 0xFFFF : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Header Length", headerLength(), byteAt(hdrOff + 1));
			h.field("MH Type", mhType(), mobilityTypeName(mhType()), byteAt(hdrOff + 2));
			h.field("Reserved", reserved(), byteAt(hdrOff + 3));
			h.fieldHex("Checksum", checksum(), 4, shortAt(hdrOff + 4));
			if (length > 6) {
				h.field("Message Data", "[" + (length - 6) + " bytes]", bits(hdrOff + 6, length - 6));
			}
		}
	}

	public final class Hip extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_HIP;

		private Hip() {
			super(HIP);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Data", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	public final class Shim6 extends Ip6Extension {
		public static final int HEADER_ID = ProtocolIds.IPv6_SHIM6;

		private Shim6() {
			super(SHIM6);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Data", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	public final class Experimental extends Ip6Extension {
		private Experimental(int id) {
			super(id);
		}

		public int headerLength() {
			return isPresent() ? buffer.get(offset + 1) & 0xFF : -1;
		}

		@Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
			int hdrOff = IP6_HEADER_LENGTH + offset;
			h.field("Next Header", nextHeader(), Ip6Extensions.extensionName(nextHeader()), byteAt(hdrOff));
			h.field("Length", headerLength(), byteAt(hdrOff + 1));
			if (length > 2) {
				h.field("Data", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
			}
		}
	}

	private final Ip6Extension[] registry = new Ip6Extension[256];

	private final HopByHop hopByHop = new HopByHop();
	private final Routing routing = new Routing();
	private final Fragment fragment = new Fragment();
	private final Destination destination = new Destination();
	private final Authentication authentication = new Authentication();
	private final Esp esp = new Esp();
	private final Mobility mobility = new Mobility();
	private final Hip hip = new Hip();
	private final Shim6 shim6 = new Shim6();
	private final Experimental experimental253 = new Experimental(EXPERIMENTAL_253);
	private final Experimental experimental254 = new Experimental(EXPERIMENTAL_254);

	Ip6Extensions() {}

	void setParent(Ip6 parent) {
		this.parent = parent;
	}

	private void register(Ip6Extension extension) {
		registry[extension.id] = extension;
	}

	@Override
	public void onUnbind() {
		parsed = false;
		buffer.unbind();
	}

	public void onBound() {
		buffer.bind(this);
	}

	private void setPresent(int id) {
		switch (id >> 6) {
		case 0 -> bitmask0 |= (1L << id);
		case 1 -> bitmask1 |= (1L << (id - 64));
		case 2 -> bitmask2 |= (1L << (id - 128));
		case 3 -> bitmask3 |= (1L << (id - 192));
		}
	}

	public boolean hasHopByHopExtension() {
		return hopByHop.isPresent();
	}

	public boolean hasRoutingExtension() {
		return routing.isPresent();
	}

	public boolean hasFragmentExtension() {
		return fragment.isPresent();
	}

	public boolean hasDestinationExtension() {
		return destination.isPresent();
	}

	public boolean hasAuthenticationExtension() {
		return authentication.isPresent();
	}

	public boolean hasEspExtension() {
		return esp.isPresent();
	}

	public boolean hasMobilityExtension() {
		return mobility.isPresent();
	}

	public boolean hasHipExtension() {
		return hip.isPresent();
	}

	public boolean hasShim6Extension() {
		return shim6.isPresent();
	}

	public boolean hasExperimental253Extension() {
		return experimental253.isPresent();
	}

	public boolean hasExperimental254Extension() {
		return experimental254.isPresent();
	}

	public boolean isFragmented() {
		return hasFragmentExtension();
	}

	public boolean hasSecurityExtensions() {
		return hasAuthenticationExtension() || hasEspExtension();
	}

	public HopByHop hopByHopExtension() {
		return hopByHop;
	}

	public Routing routingExtension() {
		return routing;
	}

	public Fragment fragmentExtension() {
		return fragment;
	}

	public Destination destinationExtension() {
		return destination;
	}

	public Authentication authenticationExtension() {
		return authentication;
	}

	public Esp espExtension() {
		return esp;
	}

	public Mobility mobilityExtension() {
		return mobility;
	}

	public Hip hipExtension() {
		return hip;
	}

	public Shim6 shim6Extension() {
		return shim6;
	}

	public Experimental experimental253Extension() {
		return experimental253;
	}

	public Experimental experimental254Extension() {
		return experimental254;
	}

	@Override
	public boolean hasExtension(int id) {
		ensureParsed();
		return switch (id >> 6) {
		case 0 -> (bitmask0 & (1L << id)) != 0;
		case 1 -> (bitmask1 & (1L << (id - 64))) != 0;
		case 2 -> (bitmask2 & (1L << (id - 128))) != 0;
		case 3 -> (bitmask3 & (1L << (id - 192))) != 0;
		default -> false;
		};
	}

	@Override
	public Ip6Extension extension(int id) {
		ensureParsed();
		return registry[id];
	}

	public int finalProtocol() {
		ensureParsed();
		return finalProtocol;
	}

	@Override
	public long totalLength() {
		ensureParsed();
		long total = 0;
		for (int i = 0; i < chainLength; i++) {
			Ip6Extension ext = registry[chain[i]];
			if (ext != null) {
				total += ext.length;
			}
		}
		return total;
	}

	@Override
	public int count() {
		ensureParsed();
		return chainLength;
	}

	@Override
	public Iterator<Ip6Extension> iterator() {
		ensureParsed();
		return new ExtensionIterator();
	}

	private class ExtensionIterator implements Iterator<Ip6Extension> {
		private int index = 0;

		@Override
		public boolean hasNext() {
			return index < chainLength;
		}

		@Override
		public Ip6Extension next() {
			if (!hasNext())
				throw new NoSuchElementException();
			Ip6Extension ext = registry[chain[index++]];
			return ext != null ? ext : new Ip6Extension(chain[index - 1]);
		}
	}

	private void ensureParsed() {
		if (!parsed) {
			parse();
		}
	}

	private void parse() {
		bitmask0 = bitmask1 = bitmask2 = bitmask3 = 0;
		chainLength = 0;
		finalProtocol = -1;

		long end = buffer.limit();
		if (end <= 0) {
			finalProtocol = parent != null ? parent.nextHeader() : -1;
			parsed = true;
			return;
		}

		int nextHeader = parent != null ? parent.nextHeader() : -1;

		if (!isExtensionHeader(nextHeader)) {
			finalProtocol = nextHeader;
			parsed = true;
			return;
		}

		long pos = 0;

		while (pos < end && chainLength < MAX_EXTENSIONS) {
			if (!isExtensionHeader(nextHeader)) {
				finalProtocol = nextHeader;
				break;
			}

			if (nextHeader == NO_NEXT_HEADER) {
				finalProtocol = NO_NEXT_HEADER;
				break;
			}

			int extId = nextHeader;

			if (pos + 2 > end && extId != FRAGMENT)
				break;

			nextHeader = buffer.get(pos) & 0xFF;

			long extLen;
			if (extId == FRAGMENT) {
				extLen = FRAGMENT_LENGTH;
			} else if (extId == AH) {
				int lenField = buffer.get(pos + 1) & 0xFF;
				extLen = (lenField + 2) * 4;
			} else {
				int lenField = buffer.get(pos + 1) & 0xFF;
				extLen = (lenField + 1) * 8;
			}

			if (pos + extLen > end)
				break;
			if (extLen < MIN_EXTENSION_LENGTH && extId != FRAGMENT)
				break;

			setPresent(extId);
			chain[chainLength++] = extId;

			Ip6Extension ext = registry[extId];
			if (ext != null) {
				ext.offset = (int) pos;
				ext.length = (int) extLen;
			}

			pos += extLen;
		}

		if (finalProtocol < 0) {
			if (chainLength > 0) {
				int lastId = chain[chainLength - 1];
				Ip6Extension lastExt = registry[lastId];
				if (lastExt != null) {
					finalProtocol = buffer.get(lastExt.offset) & 0xFF;
				}
			} else if (parent != null) {
				finalProtocol = parent.nextHeader();
			}
		}

		parsed = true;
	}

	public static boolean isExtensionHeader(int nextHeader) {
		return switch (nextHeader) {
		case HOP_BY_HOP, ROUTING, FRAGMENT, ESP, AH, DESTINATION,
				MOBILITY, HIP, SHIM6, EXPERIMENTAL_253, EXPERIMENTAL_254 -> true;
		default -> false;
		};
	}

	public static boolean isUpperLayerProtocol(int nextHeader) {
		return switch (nextHeader) {
		case TCP, UDP, ICMPV6, NO_NEXT_HEADER -> true;
		default -> !isExtensionHeader(nextHeader);
		};
	}

	public static String extensionName(int id) {
		return switch (id) {
		case HOP_BY_HOP -> "Hop-by-Hop Options";
		case ROUTING -> "Routing";
		case FRAGMENT -> "Fragment";
		case ESP -> "Encapsulating Security Payload";
		case AH -> "Authentication Header";
		case DESTINATION -> "Destination Options";
		case MOBILITY -> "Mobility";
		case HIP -> "Host Identity Protocol";
		case SHIM6 -> "Shim6";
		case NO_NEXT_HEADER -> "No Next Header";
		case TCP -> "TCP";
		case UDP -> "UDP";
		case ICMPV6 -> "ICMPv6";
		case IPV6_IN_IPV6 -> "IPv6-in-IPv6";
		case EXPERIMENTAL_253 -> "Experimental (253)";
		case EXPERIMENTAL_254 -> "Experimental (254)";
		default -> "Unknown (" + id + ")";
		};
	}

	public static String routingTypeName(int type) {
		return switch (type) {
		case ROUTING_TYPE_SOURCE -> "Source Route (deprecated)";
		case ROUTING_TYPE_NIMROD -> "Nimrod (deprecated)";
		case ROUTING_TYPE_MOBILE_IPV6 -> "Mobile IPv6";
		case ROUTING_TYPE_RPL -> "RPL Source Route";
		case ROUTING_TYPE_SEGMENT -> "Segment Routing";
		default -> "Unknown (" + type + ")";
		};
	}

	public static String mobilityTypeName(int type) {
		return switch (type) {
		case MOBILITY_BRR -> "Binding Refresh Request";
		case MOBILITY_HOTI -> "Home Test Init";
		case MOBILITY_COTI -> "Care-of Test Init";
		case MOBILITY_HOT -> "Home Test";
		case MOBILITY_COT -> "Care-of Test";
		case MOBILITY_BU -> "Binding Update";
		case MOBILITY_BA -> "Binding Acknowledgement";
		case MOBILITY_BE -> "Binding Error";
		case MOBILITY_FBU -> "Fast Binding Update";
		case MOBILITY_FBACK -> "Fast Binding Acknowledgement";
		case MOBILITY_FNA -> "Fast Neighbor Advertisement";
		default -> "Unknown (" + type + ")";
		};
	}

	public boolean validateExtensions() {
		ensureParsed();

		if (chainLength == 0)
			return true;

		if (hasExtension(HOP_BY_HOP) && chain[0] != HOP_BY_HOP) {
			return false;
		}

		int fragmentCount = 0;
		for (int i = 0; i < chainLength; i++) {
			if (chain[i] == FRAGMENT)
				fragmentCount++;
		}
		if (fragmentCount > 1)
			return false;

		return true;
	}

	private static String formatIp6(byte[] addr) {
		if (addr == null || addr.length != 16)
			return "::";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 16; i += 2) {
			if (i > 0)
				sb.append(':');
			int val = ((addr[i] & 0xFF) << 8) | (addr[i + 1] & 0xFF);
			sb.append(Integer.toHexString(val));
		}
		return sb.toString();
	}

	@Override
	public void buildDetail(DetailBuilder b) {
		ensureParsed();
		if (chainLength == 0)
			return;

		for (Ip6Extension ext : this) {
			int hdrOff = IP6_HEADER_LENGTH + ext.offset;
			b.header("IPv6 Extension - " + ext.extensionName(), "IPv6:Ext", ext.id, hdrOff, ext.length,
					ext::buildDetail);
		}
	}

	@Override
	public String toString() {
		return new TextRenderer().render(getDetail());
	}
}