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
package com.slytechs.sdk.protocol.tcpip.tcp;

import java.util.Iterator;
import java.util.NoSuchElementException;

import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryBuffer;
import com.slytechs.sdk.protocol.core.header.HeaderOption;
import com.slytechs.sdk.protocol.core.header.HeaderOptions;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * TCP options container with zero-allocation inner option classes.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class TcpOptions extends BoundView
		implements HeaderOptions<TcpOptions.TcpOption>,
		Iterable<TcpOptions.TcpOption> {

	public static final int EOL = 0;
	public static final int NOP = 1;
	public static final int MSS = 2;
	public static final int WINDOW_SCALE = 3;
	public static final int WSCALE = 3;
	public static final int SACK_PERMITTED = 4;
	public static final int SACK = 5;
	public static final int TIMESTAMPS = 8;
	public static final int TSOPT = 8;
	@Deprecated
	public static final int ECHO = 6;
	@Deprecated
	public static final int ECHO_REPLY = 7;
	@Deprecated
	public static final int POC_PERMITTED = 9;
	@Deprecated
	public static final int POC_SERVICE_PROFILE = 10;
	@Deprecated
	public static final int CC = 11;
	@Deprecated
	public static final int CC_NEW = 12;
	@Deprecated
	public static final int CC_ECHO = 13;
	@Deprecated
	public static final int ALT_CHECKSUM_REQUEST = 14;
	@Deprecated
	public static final int ALT_CHECKSUM_DATA = 15;
	@Deprecated
	public static final int SKEETER = 16;
	@Deprecated
	public static final int BUBBA = 17;
	@Deprecated
	public static final int TRAILER_CHECKSUM = 18;
	public static final int MD5_SIGNATURE = 19;
	public static final int SCPS_CAPABILITIES = 20;
	public static final int SELECTIVE_NACK = 21;
	public static final int RECORD_BOUNDARIES = 22;
	public static final int CORRUPTION_EXPERIENCED = 23;
	@Deprecated
	public static final int SNAP = 24;
	@Deprecated
	public static final int TCP_COMPRESSION_FILTER = 26;
	public static final int QUICK_START = 27;
	public static final int QS = 27;
	public static final int USER_TIMEOUT = 28;
	public static final int UTO = 28;
	public static final int TCP_AO = 29;
	public static final int AUTHENTICATION = 29;
	public static final int MPTCP = 30;
	public static final int MULTIPATH_TCP = 30;
	public static final int FAST_OPEN = 34;
	public static final int TFO = 34;
	public static final int ENCRYPTION_NEGOTIATION = 69;
	public static final int TCP_ENO = 69;
	public static final int ACCECN_ORDER_0 = 172;
	public static final int ACCECN_ORDER_1 = 174;
	public static final int EXPERIMENT_1 = 253;
	public static final int EXPERIMENT_2 = 254;

	public static final int MPTCP_MP_CAPABLE = 0;
	public static final int MPTCP_MP_JOIN = 1;
	public static final int MPTCP_DSS = 2;
	public static final int MPTCP_ADD_ADDR = 3;
	public static final int MPTCP_REMOVE_ADDR = 4;
	public static final int MPTCP_MP_PRIO = 5;
	public static final int MPTCP_MP_FAIL = 6;
	public static final int MPTCP_MP_FASTCLOSE = 7;
	public static final int MPTCP_MP_TCPRST = 8;

	private static final int TCP_HEADER_MIN = 20;
	private static final int MAX_OPTIONS = 32;
	private static final int DEFAULT_MSS = 536;

	private long bitmask0;
	private long bitmask1;
	private long bitmask2;
	private long bitmask3;

	private final int[] chain = new int[MAX_OPTIONS];
	private int chainLength;
	private boolean parsed;

	public class TcpOption implements HeaderOption {
		protected final int id;
		protected int offset;
		protected int length;

		protected TcpOption(int id) {
			this.id = id;
			register(this);
		}

		@Override
		public final int optionId() {
			return id;
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
			return switch (id >> 6) {
			case 0 -> (bitmask0 & (1L << id)) != 0;
			case 1 -> (bitmask1 & (1L << (id - 64))) != 0;
			case 2 -> (bitmask2 & (1L << (id - 128))) != 0;
			case 3 -> (bitmask3 & (1L << (id - 192))) != 0;
			default -> false;
			};
		}

		@Override
		public String optionName() {
			return TcpOptions.optionName(id);
		}

		@Override
		public String optionAbbr() {
			return TcpOptions.optionAbbr(id);
		}

		void bind(int offset, int length) {
			this.offset = offset;
			this.length = length;
		}
	}

	public final class Mss extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_MSS;

		private Mss() {
			super(MSS);
		}

		public int mss() {
			return isPresent() ? buffer.getShortBE(offset + 2) & 0xFFFF : DEFAULT_MSS;
		}

	}

	public final class WindowScale extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_WSCALE;

		private WindowScale() {
			super(WINDOW_SCALE);
		}

		public int shiftCount() {
			return isPresent() ? buffer.get(offset + 2) & 0x0F : 0;
		}

		public int multiplier() {
			return 1 << shiftCount();
		}
	}

	public final class SackPermitted extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_SACK_PERM;

		private SackPermitted() {
			super(SACK_PERMITTED);
		}
	}

	public final class Sack extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_SACK;

		private Sack() {
			super(SACK);
		}

		public int blockCount() {
			return isPresent() ? (length - 2) / 8 : 0;
		}

		public long leftEdge(int index) {
			if (!isPresent() || index < 0 || index >= blockCount())
				return -1;
			return buffer.getIntBE(offset + 2 + index * 8) & 0xFFFFFFFFL;
		}

		public long rightEdge(int index) {
			if (!isPresent() || index < 0 || index >= blockCount())
				return -1;
			return buffer.getIntBE(offset + 6 + index * 8) & 0xFFFFFFFFL;
		}
	}

	public final class Timestamps extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_TIMESTAMP;

		private Timestamps() {
			super(TIMESTAMPS);
		}

		public long tsVal() {
			return isPresent() ? buffer.getIntBE(offset + 2) & 0xFFFFFFFFL : -1;
		}

		public long tsEcr() {
			return isPresent() ? buffer.getIntBE(offset + 6) & 0xFFFFFFFFL : -1;
		}
	}

	public final class Md5Signature extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_MD5;

		private Md5Signature() {
			super(MD5_SIGNATURE);
		}

		public int digestLength() {
			return isPresent() ? length - 2 : 0;
		}

		public int digestOffset() {
			return isPresent() ? offset + 2 : -1;
		}
	}

	public final class Authentication extends TcpOption {

		private Authentication() {
			super(TCP_AO);
		}

		public int keyId() {
			return isPresent() ? buffer.get(offset + 2) & 0xFF : -1;
		}

		public int nextKeyId() {
			return isPresent() ? buffer.get(offset + 3) & 0xFF : -1;
		}

		public int macLength() {
			return isPresent() ? length - 4 : 0;
		}

		public int macOffset() {
			return isPresent() ? offset + 4 : -1;
		}
	}

	public final class QuickStart extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_FASTOPEN;

		private QuickStart() {
			super(QUICK_START);
		}

		public int function() {
			return isPresent() ? (buffer.get(offset + 2) >> 4) & 0x0F : -1;
		}

		public int rate() {
			return isPresent() ? buffer.get(offset + 2) & 0x0F : -1;
		}

		public int ttlDiff() {
			return isPresent() ? buffer.get(offset + 3) & 0xFF : -1;
		}

		public int nonce() {
			return isPresent() ? buffer.getInt(offset + 4) >>> 2 : -1;
		}
	}

	public final class UserTimeout extends TcpOption {

		private UserTimeout() {
			super(USER_TIMEOUT);
		}

		public int granularity() {
			return isPresent() ? (buffer.get(offset + 2) >> 7) & 0x01 : -1;
		}

		public int value() {
			return isPresent() ? buffer.getShort(offset + 2) & 0x7FFF : -1;
		}

		public int timeoutSeconds() {
			if (!isPresent())
				return -1;
			int raw = buffer.getShort(offset + 2) & 0xFFFF;
			int gran = (raw >> 15) & 0x01;
			int val = raw & 0x7FFF;
			return gran == 1 ? val : val * 60;
		}
	}

	public final class FastOpen extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_FASTOPEN;

		private FastOpen() {
			super(FAST_OPEN);
		}

		public int cookieLength() {
			return isPresent() ? length - 2 : 0;
		}

		public int cookieOffset() {
			return isPresent() && length > 2 ? offset + 2 : -1;
		}

		public boolean isRequest() {
			return isPresent() && cookieLength() == 0;
		}
	}

	public final class Multipath extends TcpOption {
		public static final int HEADER_ID = ProtocolIds.TCP_OPT_MPTCP;

		private Multipath() {
			super(MPTCP);
		}

		public int subtype() {
			return isPresent() ? (buffer.get(offset + 2) >> 4) & 0x0F : -1;
		}

		public int version() {
			if (!isPresent() || subtype() != MPTCP_MP_CAPABLE)
				return -1;
			return buffer.get(offset + 2) & 0x0F;
		}

		public int flags() {
			return isPresent() ? buffer.get(offset + 3) & 0xFF : -1;
		}

		public long senderKey() {
			if (!isPresent() || subtype() != MPTCP_MP_CAPABLE || length < 12)
				return -1;
			return buffer.getLong(offset + 4);
		}

		public long receiverKey() {
			if (!isPresent() || subtype() != MPTCP_MP_CAPABLE || length < 20)
				return -1;
			return buffer.getLong(offset + 12);
		}
	}

	public final class AccEcn extends TcpOption {

		private final int order;

		private AccEcn(int id, int order) {
			super(id);
			this.order = order;
		}

		public int ee0() {
			if (!isPresent() || length < 5)
				return -1;
			return ((buffer.get(offset + 2) & 0xFF) << 16) | (buffer.getShort(offset + 3) & 0xFFFF);
		}

		public int eceb() {
			if (!isPresent() || length < 8)
				return -1;
			return ((buffer.get(offset + 5) & 0xFF) << 16) | (buffer.getShort(offset + 6) & 0xFFFF);
		}

		public int ce() {
			if (!isPresent() || length < 11)
				return -1;
			return ((buffer.get(offset + 8) & 0xFF) << 16) | (buffer.getShort(offset + 9) & 0xFFFF);
		}
	}

	public final class Encryption extends TcpOption {

		private Encryption() {
			super(ENCRYPTION_NEGOTIATION);
		}

		public int dataLength() {
			return isPresent() ? length - 2 : 0;
		}

	}

	public final class Experiment extends TcpOption {
		private Experiment(int id) {
			super(id);
		}

		public int exId() {
			return isPresent() && length >= 4 ? buffer.getShort(offset + 2) & 0xFFFF : -1;
		}
	}

	private final TcpOption[] registry = new TcpOption[256];

	private final Mss mss = new Mss();
	private final WindowScale windowScale = new WindowScale();
	private final SackPermitted sackPermitted = new SackPermitted();
	private final Sack sack = new Sack();
	private final Timestamps timestamps = new Timestamps();
	private final Md5Signature md5Signature = new Md5Signature();
	private final Authentication authentication = new Authentication();
	private final QuickStart quickStart = new QuickStart();
	private final UserTimeout userTimeout = new UserTimeout();
	private final FastOpen fastOpen = new FastOpen();
	private final Multipath multipath = new Multipath();
	private final AccEcn accEcn0 = new AccEcn(ACCECN_ORDER_0, 0);
	private final AccEcn accEcn1 = new AccEcn(ACCECN_ORDER_1, 1);
	private final Encryption encryption = new Encryption();
	private final Experiment experiment1 = new Experiment(EXPERIMENT_1);
	private final Experiment experiment2 = new Experiment(EXPERIMENT_2);

	private final MemoryBuffer buffer = new MemoryBuffer();

	TcpOptions() {}

	private void register(TcpOption option) {
		registry[option.id] = option;
	}

	private void setPresent(int id) {
		switch (id >> 6) {
		case 0 -> bitmask0 |= (1L << id);
		case 1 -> bitmask1 |= (1L << (id - 64));
		case 2 -> bitmask2 |= (1L << (id - 128));
		case 3 -> bitmask3 |= (1L << (id - 192));
		}
	}

	public boolean hasMssOption() {
		return mss.isPresent();
	}

	public boolean hasWindowScaleOption() {
		return windowScale.isPresent();
	}

	public boolean hasSackPermittedOption() {
		return sackPermitted.isPresent();
	}

	public boolean hasSackOption() {
		return sack.isPresent();
	}

	public boolean hasTimestampsOption() {
		return timestamps.isPresent();
	}

	public boolean hasMd5SignatureOption() {
		return md5Signature.isPresent();
	}

	public boolean hasAuthenticationOption() {
		return authentication.isPresent();
	}

	public boolean hasQuickStartOption() {
		return quickStart.isPresent();
	}

	public boolean hasUserTimeoutOption() {
		return userTimeout.isPresent();
	}

	public boolean hasFastOpenOption() {
		return fastOpen.isPresent();
	}

	public boolean hasMultipathOption() {
		return multipath.isPresent();
	}

	public boolean hasAccEcn0Option() {
		return accEcn0.isPresent();
	}

	public boolean hasAccEcn1Option() {
		return accEcn1.isPresent();
	}

	public boolean hasAccEcnOption() {
		return hasAccEcn0Option() || hasAccEcn1Option();
	}

	public boolean hasEncryptionOption() {
		return encryption.isPresent();
	}

	public boolean hasExperiment1Option() {
		return experiment1.isPresent();
	}

	public boolean hasExperiment2Option() {
		return experiment2.isPresent();
	}

	public Mss mssOption() {
		return mss;
	}

	public WindowScale windowScaleOption() {
		return windowScale;
	}

	public SackPermitted sackPermittedOption() {
		return sackPermitted;
	}

	public Sack sackOption() {
		return sack;
	}

	public Timestamps timestampsOption() {
		return timestamps;
	}

	public Md5Signature md5SignatureOption() {
		return md5Signature;
	}

	public Authentication authenticationOption() {
		return authentication;
	}

	public QuickStart quickStartOption() {
		return quickStart;
	}

	public UserTimeout userTimeoutOption() {
		return userTimeout;
	}

	public FastOpen fastOpenOption() {
		return fastOpen;
	}

	public Multipath multipathOption() {
		return multipath;
	}

	public AccEcn accEcn0Option() {
		return accEcn0;
	}

	public AccEcn accEcn1Option() {
		return accEcn1;
	}

	public Encryption encryptionOption() {
		return encryption;
	}

	public Experiment experiment1Option() {
		return experiment1;
	}

	public Experiment experiment2Option() {
		return experiment2;
	}

	@Override
	public boolean hasOption(int id) {
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
	public TcpOption option(int id) {
		ensureParsed();
		return registry[id];
	}

	@Override
	public int count() {
		ensureParsed();
		return chainLength;
	}

	@Override
	public Iterator<TcpOption> iterator() {
		ensureParsed();
		return new OptionIterator();
	}

	private class OptionIterator implements Iterator<TcpOption> {
		private int index = 0;

		@Override
		public boolean hasNext() {
			return index < chainLength;
		}

		@Override
		public TcpOption next() {
			if (!hasNext())
				throw new NoSuchElementException();
			TcpOption opt = registry[chain[index++]];
			return opt != null ? opt : new TcpOption(chain[index - 1]);
		}
	}

	// Remove the bind() method entirely. Parent TCP handles super.bind()

	@Override
	public void onUnbind() {
		parsed = false;
		buffer.unbind();
	}

	@Override
	public void onBind() {
		buffer.bind(this);
	}

	private void ensureParsed() {
		if (!parsed) {
			parse();
		}
	}

	private void parse() {
		// Reset state at start of parse
		bitmask0 = bitmask1 = bitmask2 = bitmask3 = 0;
		chainLength = 0;

		long pos = 0;
		long end = buffer.limit();

		while (pos < end && chainLength < MAX_OPTIONS) {
			int kind = buffer.get(pos) & 0xFF;

			if (kind == EOL)
				break;

			if (kind == NOP) {
				pos++;
				continue;
			}

			if (pos + 1 >= end)
				break;

			int len = buffer.get(pos + 1) & 0xFF;
			if (len < 2 || pos + len > end)
				break;

			setPresent(kind);
			chain[chainLength++] = kind;

			TcpOption opt = registry[kind];
			if (opt != null) {
				opt.offset = (int) pos;
				opt.length = len;
			}

			pos += len;
		}

		parsed = true;
	}

	public static String optionName(int kind) {
		return switch (kind) {
		case EOL -> "End of Option List";
		case NOP -> "No Operation";
		case MSS -> "Maximum Segment Size";
		case WINDOW_SCALE -> "Window Scale";
		case SACK_PERMITTED -> "SACK Permitted";
		case SACK -> "SACK";
		case ECHO -> "Echo (deprecated)";
		case ECHO_REPLY -> "Echo Reply (deprecated)";
		case TIMESTAMPS -> "Timestamps";
		case MD5_SIGNATURE -> "MD5 Signature";
		case TCP_AO -> "TCP Authentication";
		case MPTCP -> "Multipath TCP";
		case FAST_OPEN -> "TCP Fast Open";
		case USER_TIMEOUT -> "User Timeout";
		case QUICK_START -> "Quick-Start";
		case ENCRYPTION_NEGOTIATION -> "Encryption Negotiation";
		case ACCECN_ORDER_0 -> "AccECN Order 0";
		case ACCECN_ORDER_1 -> "AccECN Order 1";
		case EXPERIMENT_1 -> "Experiment 1";
		case EXPERIMENT_2 -> "Experiment 2";
		default -> "Unknown (" + kind + ")";
		};
	}

	// Static method in TcpOptions
	public static String optionAbbr(int kind) {
		return switch (kind) {
		case MSS -> "MSS";
		case WINDOW_SCALE -> "WS";
		case SACK_PERMITTED -> "SACKP";
		case SACK -> "SACK";
		case TIMESTAMPS -> "TS";
		case FAST_OPEN -> "TFO";
		case MPTCP -> "MPTCP";
		case USER_TIMEOUT -> "UTO";
		case TCP_AO -> "AO";
		case MD5_SIGNATURE -> "MD5";
		case QUICK_START -> "QS";
		default -> String.valueOf(kind);
		};
	}

	public static String mptcpSubtypeName(int subtype) {
		return switch (subtype) {
		case MPTCP_MP_CAPABLE -> "MP_CAPABLE";
		case MPTCP_MP_JOIN -> "MP_JOIN";
		case MPTCP_DSS -> "DSS";
		case MPTCP_ADD_ADDR -> "ADD_ADDR";
		case MPTCP_REMOVE_ADDR -> "REMOVE_ADDR";
		case MPTCP_MP_PRIO -> "MP_PRIO";
		case MPTCP_MP_FAIL -> "MP_FAIL";
		case MPTCP_MP_FASTCLOSE -> "MP_FASTCLOSE";
		case MPTCP_MP_TCPRST -> "MP_TCPRST";
		default -> "Unknown (" + subtype + ")";
		};
	}

}