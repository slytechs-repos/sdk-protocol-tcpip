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
import com.slytechs.sdk.common.memory.ByteBuf;
import com.slytechs.sdk.protocol.core.HeaderOption;
import com.slytechs.sdk.protocol.core.HeaderOptions;
import com.slytechs.sdk.protocol.core.ProtocolId;

/**
 * IPv4 options container with zero-allocation inner option classes.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class Ip4Options extends ByteBuf implements HeaderOptions<Ip4Options.Ip4Option>, Detailable, Iterable<Ip4Options.Ip4Option> {

    public static final int EOOL = 0;
    public static final int NOP = 1;
    public static final int SEC = 130;
    public static final int SECURITY = 130;
    public static final int LSR = 131;
    public static final int LOOSE_SOURCE_ROUTE = 131;
    public static final int TS = 68;
    public static final int TIMESTAMP = 68;
    public static final int E_SEC = 133;
    public static final int EXTENDED_SECURITY = 133;
    public static final int CIPSO = 134;
    public static final int COMMERCIAL_SECURITY = 134;
    public static final int RR = 7;
    public static final int RECORD_ROUTE = 7;
    @Deprecated public static final int SID = 136;
    @Deprecated public static final int STREAM_ID = 136;
    public static final int SSR = 137;
    public static final int STRICT_SOURCE_ROUTE = 137;
    public static final int ZSU = 10;
    public static final int MTUP = 11;
    public static final int MTU_PROBE = 11;
    public static final int MTUR = 12;
    public static final int MTU_REPLY = 12;
    public static final int FINN = 205;
    public static final int VISA = 142;
    public static final int ENCODE = 15;
    public static final int IMITD = 144;
    public static final int IMI_TRAFFIC_DESCRIPTOR = 144;
    public static final int EIP = 145;
    public static final int EXTENDED_IP = 145;
    public static final int TR = 82;
    public static final int TRACEROUTE = 82;
    public static final int ADDEXT = 147;
    public static final int ADDRESS_EXTENSION = 147;
    public static final int RTRALT = 148;
    public static final int ROUTER_ALERT = 148;
    public static final int SDB = 149;
    public static final int SELECTIVE_DIRECTED_BROADCAST = 149;
    public static final int DPS = 151;
    public static final int DYNAMIC_PACKET_STATE = 151;
    public static final int UMP = 152;
    public static final int UPSTREAM_MULTICAST = 152;
    public static final int QS = 25;
    public static final int QUICK_START = 25;
    public static final int EXP = 30;
    public static final int EXPERIMENT = 30;

    public static final int TYPE_COPIED_MASK = 0x80;
    public static final int TYPE_CLASS_MASK = 0x60;
    public static final int TYPE_NUMBER_MASK = 0x1F;

    public static final int CLASS_CONTROL = 0;
    public static final int CLASS_RESERVED1 = 1;
    public static final int CLASS_DEBUG_MEASURE = 2;
    public static final int CLASS_RESERVED2 = 3;

    public static final int ROUTER_ALERT_EXAMINE = 0;

    public static final int TS_FLAG_TSONLY = 0;
    public static final int TS_FLAG_TSADDR = 1;
    public static final int TS_FLAG_PRESPEC = 3;

    public static final int SEC_UNCLASSIFIED = 0x00;
    public static final int SEC_CONFIDENTIAL = 0xF1;
    public static final int SEC_SECRET = 0x5A;
    public static final int SEC_TOP_SECRET = 0x96;

    private static final int IP4_HEADER_MIN = 20;
    private static final int MAX_OPTIONS = 32;

    private long bitmask0;
    private long bitmask1;
    private long bitmask2;
    private long bitmask3;

    private final int[] chain = new int[MAX_OPTIONS];
    private int chainLength;
    private boolean parsed;

    public class Ip4Option implements HeaderOption {
        protected final int type;
        protected int offset;
        protected int length;

        protected Ip4Option(int type) {
            this.type = type;
            register(this);
        }

        public final int optionType() {
            return type;
        }

        @Override
		public final int optionOffset() {
            return offset;
        }

        @Override
		public final int optionLength() {
            return length;
        }

        @Override
		public final boolean isPresent() {
            ensureParsed();
            return switch (type >> 6) {
                case 0 -> (bitmask0 & (1L << type)) != 0;
                case 1 -> (bitmask1 & (1L << (type - 64))) != 0;
                case 2 -> (bitmask2 & (1L << (type - 128))) != 0;
                case 3 -> (bitmask3 & (1L << (type - 192))) != 0;
                default -> false;
            };
        }

        public final boolean isCopied() {
            return (type & TYPE_COPIED_MASK) != 0;
        }

        public final int optionClass() {
            return (type & TYPE_CLASS_MASK) >> 5;
        }

        public final int optionNumber() {
            return type & TYPE_NUMBER_MASK;
        }

        @Override
		public String optionName() {
            return Ip4Options.optionName(type);
        }

        @Override
		public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            h.expandField("Type", type, formatType(type), byteAt(hdrOff), f -> {
                f.field("Copied", isCopied() ? 1 : 0, isCopied() ? "Yes" : "No", bitsAt(hdrOff * 8L, 1));
                f.field("Class", optionClass(), className(optionClass()), bitsAt(hdrOff * 8L + 1, 2));
                f.field("Number", optionNumber(), bitsAt(hdrOff * 8L + 3, 5));
            });
            h.field("Length", length, byteAt(hdrOff + 1));
            if (length > 2) {
                h.field("Data", "[" + (length - 2) + " bytes]", bits(hdrOff + 2, length - 2));
            }
        }

		/**
		 * @see com.slytechs.sdk.protocol.core.HeaderOption#optionId()
		 */
		@Override
		public int optionId() {
			return type;
		}

		/**
		 * @see com.slytechs.sdk.protocol.core.HeaderOption#optionAbbr()
		 */
		@Override
		public String optionAbbr() {
			throw new UnsupportedOperationException("not implemented yet");
		}
    }

    public final class Security extends Ip4Option {
    	public static final int HEADER_ID = ProtocolId.IPv4_OPT_SECURITY;
        private Security() { super(SEC); }

        public int level() {
            return isPresent() ? get(offset + 2) & 0xFF : -1;
        }

        public int compartments() {
            return isPresent() ? getShort(offset + 3) & 0xFFFF : -1;
        }

        public int handling() {
            return isPresent() ? getShort(offset + 5) & 0xFFFF : -1;
        }

        public int tcc() {
            if (!isPresent()) return -1;
            return ((get(offset + 7) & 0xFF) << 16) | (getShort(offset + 8) & 0xFFFF);
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Classification", level(), securityLevelName(level()), byteAt(hdrOff + 2));
            h.fieldHex("Compartments", compartments(), 4, shortAt(hdrOff + 3));
            h.fieldHex("Handling", handling(), 4, shortAt(hdrOff + 5));
            h.fieldHex("TCC", tcc(), 6, bits(hdrOff + 7, 3));
        }
    }

    public final class LooseSourceRoute extends Ip4Option {
		public static final int HEADER_ID = ProtocolId.IPv4_OPT_LSRR;

	       private LooseSourceRoute() { super(LSR); }

        public int pointer() {
            return isPresent() ? get(offset + 2) & 0xFF : -1;
        }

        public int addressCount() {
            return isPresent() ? (length - 3) / 4 : 0;
        }

        public int address(int index) {
            if (!isPresent() || index < 0 || index >= addressCount()) return 0;
            return getInt(offset + 3 + index * 4);
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Pointer", pointer(), byteAt(hdrOff + 2));
            for (int i = 0; i < addressCount(); i++) {
                int idx = i;
                h.field("Route " + i, formatIp4(address(idx)), intAt(hdrOff + 3 + i * 4));
            }
        }
    }

    public final class StrictSourceRoute extends Ip4Option {
    	public static final int HEADER_ID = ProtocolId.IPv4_OPT_SSRR;

        private StrictSourceRoute() { super(SSR); }

        public int pointer() {
            return isPresent() ? get(offset + 2) & 0xFF : -1;
        }

        public int addressCount() {
            return isPresent() ? (length - 3) / 4 : 0;
        }

        public int address(int index) {
            if (!isPresent() || index < 0 || index >= addressCount()) return 0;
            return getInt(offset + 3 + index * 4);
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Pointer", pointer(), byteAt(hdrOff + 2));
            for (int i = 0; i < addressCount(); i++) {
                int idx = i;
                h.field("Route " + i, formatIp4(address(idx)), intAt(hdrOff + 3 + i * 4));
            }
        }
    }

    public final class RecordRoute extends Ip4Option {
    	public static final int HEADER_ID = ProtocolId.IPv4_OPT_RR;
        private RecordRoute() { super(RR); }

        public int pointer() {
            return isPresent() ? get(offset + 2) & 0xFF : -1;
        }

        public int recordedCount() {
            if (!isPresent()) return 0;
            return Math.max(0, (pointer() - 4) / 4);
        }

        public int capacity() {
            return isPresent() ? (length - 3) / 4 : 0;
        }

        public int address(int index) {
            if (!isPresent() || index < 0 || index >= capacity()) return 0;
            return getInt(offset + 3 + index * 4);
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Pointer", pointer(), byteAt(hdrOff + 2));
            int recorded = recordedCount();
            for (int i = 0; i < capacity(); i++) {
                int idx = i;
                String label = i < recorded ? "Recorded " + i : "Empty " + i;
                h.field(label, formatIp4(address(idx)), intAt(hdrOff + 3 + i * 4));
            }
        }
    }

    public final class Timestamp extends Ip4Option {
    	public static final int HEADER_ID = ProtocolId.IPv4_OPT_TIMESTAMP;
    	
        private Timestamp() { super(TS); }

        public int pointer() {
            return isPresent() ? get(offset + 2) & 0xFF : -1;
        }

        public int overflow() {
            return isPresent() ? (get(offset + 3) >> 4) & 0x0F : -1;
        }

        public int flag() {
            return isPresent() ? get(offset + 3) & 0x0F : -1;
        }

        public int entryCount() {
            if (!isPresent()) return 0;
            int dataLen = length - 4;
            return flag() == TS_FLAG_TSONLY ? dataLen / 4 : dataLen / 8;
        }

        public long timestamp(int index) {
            if (!isPresent() || index < 0 || index >= entryCount()) return -1;
            int entryOff = offset + 4;
            if (flag() == TS_FLAG_TSONLY) {
                return getInt(entryOff + index * 4) & 0xFFFFFFFFL;
            } else {
                return getInt(entryOff + index * 8 + 4) & 0xFFFFFFFFL;
            }
        }

        public int address(int index) {
            if (!isPresent() || index < 0 || index >= entryCount()) return 0;
            if (flag() == TS_FLAG_TSONLY) return 0;
            return getInt(offset + 4 + index * 8);
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Pointer", pointer(), byteAt(hdrOff + 2));
            h.expandField("Overflow/Flag", get(offset + 3) & 0xFF,
                    String.format("oflw=%d, flag=%d", overflow(), flag()),
                    byteAt(hdrOff + 3), f -> {
                        f.field("Overflow", overflow(), bitsAt((hdrOff + 3) * 8L, 4));
                        f.field("Flag", flag(), tsFlagName(flag()), bitsAt((hdrOff + 3) * 8L + 4, 4));
                    });

            int flg = flag();
            for (int i = 0; i < entryCount(); i++) {
                int idx = i;
                if (flg == TS_FLAG_TSONLY) {
                    h.field("Timestamp " + i, timestamp(idx), intAt(hdrOff + 4 + i * 4));
                } else {
                    int entryOff = hdrOff + 4 + i * 8;
                    h.section("Entry " + i, "", s -> {
                        s.field("Address", formatIp4(address(idx)), intAt(entryOff));
                        s.field("Timestamp", timestamp(idx), intAt(entryOff + 4));
                    });
                }
            }
        }
    }

    public final class RouterAlert extends Ip4Option {
    	public static final int HEADER_ID = ProtocolId.IPv4_OPT_RA;
        private RouterAlert() { super(RTRALT); }

        public int value() {
            return isPresent() ? getShort(offset + 2) & 0xFFFF : -1;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            String valueStr = value() == ROUTER_ALERT_EXAMINE ? "Examine packet" : String.valueOf(value());
            h.field("Value", value(), valueStr, shortAt(hdrOff + 2));
        }
    }

    public final class Traceroute extends Ip4Option {
        private Traceroute() { super(TR); }

        public int id() {
            return isPresent() ? getShort(offset + 2) & 0xFFFF : -1;
        }

        public int outboundHops() {
            return isPresent() ? getShort(offset + 4) & 0xFFFF : -1;
        }

        public int returnHops() {
            return isPresent() ? getShort(offset + 6) & 0xFFFF : -1;
        }

        public int originator() {
            return isPresent() ? getInt(offset + 8) : 0;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("HEADER_ID", id(), shortAt(hdrOff + 2));
            h.field("Outbound Hops", outboundHops(), shortAt(hdrOff + 4));
            h.field("Return Hops", returnHops(), shortAt(hdrOff + 6));
            h.field("Originator", formatIp4(originator()), intAt(hdrOff + 8));
        }
    }

    public final class QuickStart extends Ip4Option {
        private QuickStart() { super(QS); }

        public int function() {
            return isPresent() ? (get(offset + 2) >> 4) & 0x0F : -1;
        }

        public int rate() {
            return isPresent() ? get(offset + 2) & 0x0F : -1;
        }

        public int ttl() {
            return isPresent() ? get(offset + 3) & 0xFF : -1;
        }

        public int nonce() {
            return isPresent() ? getInt(offset + 4) >>> 2 : -1;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.expandField("Func/Rate", get(offset + 2) & 0xFF,
                    String.format("Func=%d, Rate=%d", function(), rate()),
                    byteAt(hdrOff + 2), f -> {
                        f.field("Function", function(), bitsAt((hdrOff + 2) * 8L, 4));
                        f.field("Rate", rate(), bitsAt((hdrOff + 2) * 8L + 4, 4));
                    });
            h.field("TTL", ttl(), byteAt(hdrOff + 3));
            h.fieldHex("Nonce", nonce(), 8, intAt(hdrOff + 4));
        }
    }

    @Deprecated
    public final class StreamId extends Ip4Option {
        private StreamId() { super(SID); }

        public int streamId() {
            return isPresent() ? getShort(offset + 2) & 0xFFFF : -1;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("Stream HEADER_ID", streamId(), shortAt(hdrOff + 2));
        }
    }

    public final class MtuProbe extends Ip4Option {
        private MtuProbe() { super(MTUP); }

        public int mtu() {
            return isPresent() ? getShort(offset + 2) & 0xFFFF : -1;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("MTU", mtu(), shortAt(hdrOff + 2));
        }
    }

    public final class MtuReply extends Ip4Option {
        private MtuReply() { super(MTUR); }

        public int mtu() {
            return isPresent() ? getShort(offset + 2) & 0xFFFF : -1;
        }

        @Override
        public void buildDetail(DetailBuilder.HeaderBuilder h) {
            int hdrOff = IP4_HEADER_MIN + offset;
            buildTypeField(h, hdrOff);
            h.field("Length", length, byteAt(hdrOff + 1));
            h.field("MTU", mtu(), shortAt(hdrOff + 2));
        }
    }

    public final class ExtendedSecurity extends Ip4Option {
        private ExtendedSecurity() { super(E_SEC); }
    }

    public final class CommercialSecurity extends Ip4Option {
        private CommercialSecurity() { super(CIPSO); }
    }

    public final class AddressExtension extends Ip4Option {
        private AddressExtension() { super(ADDEXT); }
    }

    public final class SelectiveDirectedBroadcast extends Ip4Option {
        private SelectiveDirectedBroadcast() { super(SDB); }
    }

    public final class DynamicPacketState extends Ip4Option {
        private DynamicPacketState() { super(DPS); }
    }

    public final class UpstreamMulticast extends Ip4Option {
        private UpstreamMulticast() { super(UMP); }
    }

    public final class ExperimentOption extends Ip4Option {
        private ExperimentOption() { super(EXP); }
    }

    private final Ip4Option[] registry = new Ip4Option[256];

    private final Security security = new Security();
    private final LooseSourceRoute looseSourceRoute = new LooseSourceRoute();
    private final StrictSourceRoute strictSourceRoute = new StrictSourceRoute();
    private final RecordRoute recordRoute = new RecordRoute();
    private final Timestamp timestamp = new Timestamp();
    private final RouterAlert routerAlert = new RouterAlert();
    private final Traceroute traceroute = new Traceroute();
    private final QuickStart quickStart = new QuickStart();
    private final StreamId streamId = new StreamId();
    private final MtuProbe mtuProbe = new MtuProbe();
    private final MtuReply mtuReply = new MtuReply();
    private final ExtendedSecurity extendedSecurity = new ExtendedSecurity();
    private final CommercialSecurity commercialSecurity = new CommercialSecurity();
    private final AddressExtension addressExtension = new AddressExtension();
    private final SelectiveDirectedBroadcast selectiveDirectedBroadcast = new SelectiveDirectedBroadcast();
    private final DynamicPacketState dynamicPacketState = new DynamicPacketState();
    private final UpstreamMulticast upstreamMulticast = new UpstreamMulticast();
    private final ExperimentOption experiment = new ExperimentOption();

    Ip4Options() {}

    private void register(Ip4Option option) {
        registry[option.type] = option;
    }

    @Override
    public void onUnbind() {
        parsed = false;
    }

    private void setPresent(int type) {
        switch (type >> 6) {
            case 0 -> bitmask0 |= (1L << type);
            case 1 -> bitmask1 |= (1L << (type - 64));
            case 2 -> bitmask2 |= (1L << (type - 128));
            case 3 -> bitmask3 |= (1L << (type - 192));
        }
    }

    public boolean hasSecurityOption() { return security.isPresent(); }
    public boolean hasLooseSourceRouteOption() { return looseSourceRoute.isPresent(); }
    public boolean hasStrictSourceRouteOption() { return strictSourceRoute.isPresent(); }
    public boolean hasSourceRouteOption() { return hasLooseSourceRouteOption() || hasStrictSourceRouteOption(); }
    public boolean hasRecordRouteOption() { return recordRoute.isPresent(); }
    public boolean hasTimestampOption() { return timestamp.isPresent(); }
    public boolean hasRouterAlertOption() { return routerAlert.isPresent(); }
    public boolean hasTracerouteOption() { return traceroute.isPresent(); }
    public boolean hasQuickStartOption() { return quickStart.isPresent(); }
    @Deprecated public boolean hasStreamIdOption() { return streamId.isPresent(); }
    public boolean hasMtuProbeOption() { return mtuProbe.isPresent(); }
    public boolean hasMtuReplyOption() { return mtuReply.isPresent(); }
    public boolean hasExtendedSecurityOption() { return extendedSecurity.isPresent(); }
    public boolean hasCommercialSecurityOption() { return commercialSecurity.isPresent(); }
    public boolean hasAddressExtensionOption() { return addressExtension.isPresent(); }
    public boolean hasSelectiveDirectedBroadcastOption() { return selectiveDirectedBroadcast.isPresent(); }
    public boolean hasDynamicPacketStateOption() { return dynamicPacketState.isPresent(); }
    public boolean hasUpstreamMulticastOption() { return upstreamMulticast.isPresent(); }
    public boolean hasExperimentOption() { return experiment.isPresent(); }

    public Security securityOption() { return security; }
    public LooseSourceRoute looseSourceRouteOption() { return looseSourceRoute; }
    public StrictSourceRoute strictSourceRouteOption() { return strictSourceRoute; }
    public RecordRoute recordRouteOption() { return recordRoute; }
    public Timestamp timestampOption() { return timestamp; }
    public RouterAlert routerAlertOption() { return routerAlert; }
    public Traceroute tracerouteOption() { return traceroute; }
    public QuickStart quickStartOption() { return quickStart; }
    @Deprecated public StreamId streamIdOption() { return streamId; }
    public MtuProbe mtuProbeOption() { return mtuProbe; }
    public MtuReply mtuReplyOption() { return mtuReply; }
    public ExtendedSecurity extendedSecurityOption() { return extendedSecurity; }
    public CommercialSecurity commercialSecurityOption() { return commercialSecurity; }
    public AddressExtension addressExtensionOption() { return addressExtension; }
    public SelectiveDirectedBroadcast selectiveDirectedBroadcastOption() { return selectiveDirectedBroadcast; }
    public DynamicPacketState dynamicPacketStateOption() { return dynamicPacketState; }
    public UpstreamMulticast upstreamMulticastOption() { return upstreamMulticast; }
    public ExperimentOption experimentOption() { return experiment; }

    @Override
	public boolean hasOption(int type) {
        ensureParsed();
        return switch (type >> 6) {
            case 0 -> (bitmask0 & (1L << type)) != 0;
            case 1 -> (bitmask1 & (1L << (type - 64))) != 0;
            case 2 -> (bitmask2 & (1L << (type - 128))) != 0;
            case 3 -> (bitmask3 & (1L << (type - 192))) != 0;
            default -> false;
        };
    }

    @Override
	public Ip4Option option(int type) {
        ensureParsed();
        return registry[type];
    }

    @Override
	public int count() {
        ensureParsed();
        return chainLength;
    }

    @Override
    public Iterator<Ip4Option> iterator() {
        ensureParsed();
        return new OptionIterator();
    }

    private class OptionIterator implements Iterator<Ip4Option> {
        private int index = 0;

        @Override
        public boolean hasNext() {
            return index < chainLength;
        }

        @Override
        public Ip4Option next() {
            if (!hasNext()) throw new NoSuchElementException();
            Ip4Option opt = registry[chain[index++]];
            return opt != null ? opt : new Ip4Option(chain[index - 1]);
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

        long pos = 0;
        long end = limit();

        while (pos < end && chainLength < MAX_OPTIONS) {
            int type = get(pos) & 0xFF;

            if (type == EOOL) break;

            if (type == NOP) {
                pos++;
                continue;
            }

            if (pos + 1 >= end) break;

            int len = get(pos + 1) & 0xFF;
            if (len < 2 || pos + len > end) break;

            setPresent(type);
            chain[chainLength++] = type;

            Ip4Option opt = registry[type];
            if (opt != null) {
                opt.offset = (int) pos;
                opt.length = len;
            }

            pos += len;
        }

        parsed = true;
    }

    public static String optionName(int type) {
        return switch (type) {
            case EOOL -> "End of Options List";
            case NOP -> "No Operation";
            case SECURITY -> "Security";
            case LOOSE_SOURCE_ROUTE -> "Loose Source Route";
            case TIMESTAMP -> "Timestamp";
            case EXTENDED_SECURITY -> "Extended Security";
            case COMMERCIAL_SECURITY -> "Commercial Security (CIPSO)";
            case RECORD_ROUTE -> "Record Route";
            case STREAM_ID -> "Stream HEADER_ID (obsolete)";
            case STRICT_SOURCE_ROUTE -> "Strict Source Route";
            case ZSU -> "Experimental Measurement";
            case MTU_PROBE -> "MTU Probe";
            case MTU_REPLY -> "MTU Reply";
            case FINN -> "Experimental Flow Control";
            case VISA -> "Experimental Access Control";
            case ENCODE -> "Encode";
            case IMI_TRAFFIC_DESCRIPTOR -> "IMI Traffic Descriptor";
            case EXTENDED_IP -> "Extended IP";
            case TRACEROUTE -> "Traceroute";
            case ADDRESS_EXTENSION -> "Address Extension";
            case ROUTER_ALERT -> "Router Alert";
            case SELECTIVE_DIRECTED_BROADCAST -> "Selective Directed Broadcast";
            case DYNAMIC_PACKET_STATE -> "Dynamic Packet State";
            case UPSTREAM_MULTICAST -> "Upstream Multicast";
            case QUICK_START -> "Quick-Start";
            case EXPERIMENT -> "RFC3692 Experiment";
            default -> "Unknown (" + type + ")";
        };
    }

    public static String securityLevelName(int level) {
        return switch (level) {
            case SEC_UNCLASSIFIED -> "Unclassified";
            case SEC_CONFIDENTIAL -> "Confidential";
            case SEC_SECRET -> "Secret";
            case SEC_TOP_SECRET -> "Top Secret";
            default -> "Unknown (" + level + ")";
        };
    }

    public static String tsFlagName(int flag) {
        return switch (flag) {
            case TS_FLAG_TSONLY -> "Timestamps only";
            case TS_FLAG_TSADDR -> "Address + Timestamp";
            case TS_FLAG_PRESPEC -> "Prespecified addresses";
            default -> "Unknown (" + flag + ")";
        };
    }

    public static String className(int optClass) {
        return switch (optClass) {
            case CLASS_CONTROL -> "Control";
            case CLASS_RESERVED1 -> "Reserved";
            case CLASS_DEBUG_MEASURE -> "Debug/Measurement";
            case CLASS_RESERVED2 -> "Reserved";
            default -> "Unknown (" + optClass + ")";
        };
    }

    private void buildTypeField(DetailBuilder.HeaderBuilder h, int hdrOff) {
        int type = get(hdrOff - IP4_HEADER_MIN) & 0xFF;
        h.expandField("Type", type, formatType(type), byteAt(hdrOff), f -> {
            f.field("Copied", (type & TYPE_COPIED_MASK) != 0 ? 1 : 0,
                    (type & TYPE_COPIED_MASK) != 0 ? "Yes" : "No", bitsAt(hdrOff * 8L, 1));
            f.field("Class", (type & TYPE_CLASS_MASK) >> 5,
                    className((type & TYPE_CLASS_MASK) >> 5), bitsAt(hdrOff * 8L + 1, 2));
            f.field("Number", type & TYPE_NUMBER_MASK, bitsAt(hdrOff * 8L + 3, 5));
        });
    }

    private static String formatType(int type) {
        return String.format("0x%02X (copy=%d, class=%d, num=%d)",
                type,
                (type & TYPE_COPIED_MASK) != 0 ? 1 : 0,
                (type & TYPE_CLASS_MASK) >> 5,
                type & TYPE_NUMBER_MASK);
    }

    private static String formatIp4(int addr) {
        return String.format("%d.%d.%d.%d",
                (addr >> 24) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF,
                addr & 0xFF);
    }

    @Override
    public void buildDetail(DetailBuilder b) {
        ensureParsed();
        if (chainLength == 0) return;

        for (Ip4Option opt : this) {
            int hdrOff = IP4_HEADER_MIN + opt.offset;
            b.header("IPv4 Option - " + opt.optionName(), "IPv4:Opt", opt.type, hdrOff, opt.length, opt::buildDetail);
        }
    }

    @Override
    public String toString() {
        return new TextRenderer().render(getDetail());
    }
}