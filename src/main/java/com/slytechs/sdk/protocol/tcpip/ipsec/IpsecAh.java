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
package com.slytechs.sdk.protocol.tcpip.ipsec;

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.IntHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.protocol.core.FixedHeader;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.tcpip.ip.IpProtocolResolver;

import static java.lang.foreign.MemoryLayout.*;

/**
 * IPsec Authentication Header (AH) as defined in RFC 4302.
 * 
 * <p>
 * The Authentication Header provides data origin authentication, data
 * integrity, and optional anti-replay protection for IP datagrams. AH does not
 * provide confidentiality (encryption) - use ESP for that.
 * </p>
 * 
 * <h2>Header Format</h2>
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Header   |  Payload Len  |          RESERVED             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Security Parameters Index (SPI)               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sequence Number                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                Integrity Check Value (ICV)                    +
 * |                         (variable length)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Fields</h2>
 * <ul>
 * <li><b>Next Header</b> (8 bits) - Type of the next payload after AH</li>
 * <li><b>Payload Len</b> (8 bits) - Length of AH in 32-bit words minus 2</li>
 * <li><b>Reserved</b> (16 bits) - Reserved for future use, must be zero</li>
 * <li><b>SPI</b> (32 bits) - Security Parameters Index identifying the SA</li>
 * <li><b>Sequence Number</b> (32 bits) - Anti-replay sequence number</li>
 * <li><b>ICV</b> (variable) - Integrity Check Value (authentication data)</li>
 * </ul>
 * 
 * <h2>ICV Length</h2>
 * <p>
 * The ICV length depends on the authentication algorithm negotiated in the
 * Security Association. Common lengths are:
 * </p>
 * <ul>
 * <li>HMAC-MD5-96: 12 bytes (96 bits)</li>
 * <li>HMAC-SHA1-96: 12 bytes (96 bits)</li>
 * <li>HMAC-SHA-256-128: 16 bytes (128 bits)</li>
 * <li>HMAC-SHA-384-192: 24 bytes (192 bits)</li>
 * <li>HMAC-SHA-512-256: 32 bytes (256 bits)</li>
 * </ul>
 * 
 * {@snippet :
 * IpsecAh ah = packet.getHeader(new IpsecAh());
 * 
 * System.out.println("SPI: " + Ipsec.spiAsHex(ah.spi()));
 * System.out.println("Sequence: " + ah.sequenceNumber());
 * System.out.println("Next Protocol: " + IpProtocolResolver.resolveAbbr(ah.nextHeader()));
 * System.out.println("ICV Length: " + ah.icvLength() + " bytes");
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ipsec
 * @see IpsecEsp
 * @see <a href="https://tools.ietf.org/html/rfc4302">RFC 4302 - IP
 *      Authentication Header</a>
 */
public class IpsecAh extends FixedHeader implements Detailable {

	/** Protocol HEADER_ID for IPsec AH. */
	public static final int HEADER_ID = ProtocolId.AH;

	/** Minimum AH header length in bytes (no ICV). */
	public static final int MIN_HEADER_LENGTH = 12;

	/** AH header memory layout (fixed portion). */
	public static final MemoryLayout LAYOUT = structLayout(
			U8_BE.withName("hdr_next_header"),
			U8_BE.withName("hdr_payload_len"),
			U16_BE.withName("hdr_reserved"),
			U32_BE.withName("hdr_spi"),
			U32_BE.withName("hdr_sequence"));

	private static final ByteHandle NEXT_HEADER = new ByteHandle(LAYOUT, "hdr_next_header");
	private static final ByteHandle PAYLOAD_LEN = new ByteHandle(LAYOUT, "hdr_payload_len");
	private static final ShortHandle RESERVED = new ShortHandle(LAYOUT, "hdr_reserved");
	private static final IntHandle SPI = new IntHandle(LAYOUT, "hdr_spi");
	private static final IntHandle SEQUENCE = new IntHandle(LAYOUT, "hdr_sequence");

	/**
	 * Constructs a new IPsec AH header.
	 */
	public IpsecAh() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the Next Header field (8 bits).
	 * 
	 * <p>
	 * Identifies the type of the next payload following the Authentication Header.
	 * Uses the same values as the IPv4 Protocol or IPv6 Next Header fields.
	 * </p>
	 *
	 * @return the next header protocol number
	 * @see IpProtocolResolver
	 */
	public int nextHeader() {
		return NEXT_HEADER.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Next Header field.
	 *
	 * @param nextHeader the next header protocol number
	 */
	public void setNextHeader(int nextHeader) {
		NEXT_HEADER.setByte(view(), 0, (byte) nextHeader);
	}

	/**
	 * Returns the Payload Length field (8 bits).
	 * 
	 * <p>
	 * This field specifies the length of the AH header in 32-bit words, minus 2.
	 * For example, a value of 4 indicates a 24-byte header ((4 + 2) * 4 = 24).
	 * </p>
	 *
	 * @return the payload length field value
	 * @see #headerLength()
	 */
	public int payloadLen() {
		return PAYLOAD_LEN.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Payload Length field.
	 *
	 * @param payloadLen the payload length value
	 */
	public void setPayloadLen(int payloadLen) {
		PAYLOAD_LEN.setByte(view(), 0, (byte) payloadLen);
	}

	/**
	 * Returns the Reserved field (16 bits).
	 * 
	 * <p>
	 * Reserved for future use. Must be set to zero.
	 * </p>
	 *
	 * @return the reserved field value (should be 0)
	 */
	public int reserved() {
		return RESERVED.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the Reserved field.
	 *
	 * @param reserved the reserved value (should be 0)
	 */
	public void setReserved(int reserved) {
		RESERVED.setShort(view(), 0, (short) reserved);
	}

	/**
	 * Returns the Security Parameters Index (32 bits).
	 * 
	 * <p>
	 * The SPI is an arbitrary 32-bit value that, in combination with the
	 * destination IP address and security protocol (AH), uniquely identifies the
	 * Security Association (SA) for this datagram.
	 * </p>
	 * 
	 * <p>
	 * SPI values 0-255 are reserved by IANA.
	 * </p>
	 *
	 * @return the SPI value
	 * @see Ipsec#isReservedSpi(int)
	 */
	public int spi() {
		return SPI.getInt(view());
	}

	/**
	 * Sets the Security Parameters Index.
	 *
	 * @param spi the SPI value
	 */
	public void setSpi(int spi) {
		SPI.setInt(view(), 0, spi);
	}

	/**
	 * Returns the Sequence Number (32 bits).
	 * 
	 * <p>
	 * An unsigned 32-bit counter value that increases with each packet sent using
	 * this SA. Used for anti-replay protection. The receiver maintains a sliding
	 * window to detect replayed packets.
	 * </p>
	 *
	 * @return the sequence number
	 */
	public int sequenceNumber() {
		return SEQUENCE.getInt(view());
	}

	/**
	 * Returns the Sequence Number as an unsigned long.
	 *
	 * @return the sequence number as unsigned value (0 to 4294967295)
	 */
	public long sequenceNumberUnsigned() {
		return sequenceNumber() & 0xFFFFFFFFL;
	}

	/**
	 * Sets the Sequence Number.
	 *
	 * @param sequence the sequence number
	 */
	public void setSequenceNumber(int sequence) {
		SEQUENCE.setInt(view(), 0, sequence);
	}

	/**
	 * Returns the total AH header length in bytes.
	 * 
	 * <p>
	 * Calculated as (payloadLen + 2) * 4.
	 * </p>
	 *
	 * @return the header length in bytes
	 */
	@Override
	public long headerLength() {
		return (payloadLen() + 2) * 4L;
	}

	/**
	 * Returns the ICV (Integrity Check Value) length in bytes.
	 * 
	 * <p>
	 * The ICV length is the total header length minus the fixed 12-byte portion
	 * (Next Header + Payload Len + Reserved + SPI + Sequence).
	 * </p>
	 *
	 * @return the ICV length in bytes
	 */
	public int icvLength() {
		return (int) headerLength() - MIN_HEADER_LENGTH;
	}

	/**
	 * Checks if this header contains an ICV.
	 *
	 * @return true if ICV is present (length > 0)
	 */
	public boolean hasIcv() {
		return icvLength() > 0;
	}

	/**
	 * Returns the ICV (Integrity Check Value) as a byte array.
	 * 
	 * <p>
	 * The ICV is the authentication data computed over the IP header, AH header
	 * (with ICV set to zero), and payload using the algorithm specified in the
	 * Security Association.
	 * </p>
	 *
	 * @return the ICV bytes, or empty array if no ICV
	 */
	public byte[] icv() {
		int len = icvLength();
		if (len <= 0) {
			return new byte[0];
		}
		byte[] icv = new byte[len];
		for (int i = 0; i < len; i++) {
			icv[i] = get(MIN_HEADER_LENGTH + i);
		}
		return icv;
	}

	/**
	 * Returns the ICV as a hexadecimal string.
	 *
	 * @return the ICV in hexadecimal format, or empty string if no ICV
	 */
	public String icvAsHex() {
		byte[] icv = icv();
		if (icv.length == 0) {
			return "";
		}
		StringBuilder sb = new StringBuilder(icv.length * 2);
		for (byte b : icv) {
			sb.append("%02x".formatted(b & 0xFF));
		}
		return sb.toString();
	}

	/**
	 * Checks if the SPI is in the IANA reserved range.
	 *
	 * @return true if SPI is 0-255
	 */
	public boolean isReservedSpi() {
		return Ipsec.isReservedSpi(spi());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("IPsec Authentication Header", "AH", HEADER_ID, off, (int) headerLength(), h -> {
			h.summaryf("SPI=%s Seq=%d → %s",
					Ipsec.spiAsHex(spi()),
					sequenceNumberUnsigned(),
					IpProtocolResolver.resolveAbbrOrNumber(nextHeader()));

			h.field("Next Header", nextHeader(),
					IpProtocolResolver.resolveOrNumber(nextHeader()),
					byteAt(off));
			h.field("Payload Length", payloadLen(),
					headerLength() + " bytes",
					byteAt(off + 1));
			h.fieldHex("Reserved", reserved(), 4, shortAt(off + 2));
			h.fieldHex("SPI", spi(), 8, intAt(off + 4));
			h.field("Sequence Number", sequenceNumberUnsigned(), intAt(off + 8));

			if (hasIcv()) {
				h.field("ICV", icvAsHex(),
						icvLength() + " bytes",
						bits(off + 12, icvLength()));
			}
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