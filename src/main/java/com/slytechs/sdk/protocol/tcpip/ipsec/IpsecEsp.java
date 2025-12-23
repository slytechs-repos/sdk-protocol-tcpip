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
import com.slytechs.sdk.common.memory.MemoryHandle.IntHandle;
import com.slytechs.sdk.protocol.core.FixedHeader;
import com.slytechs.sdk.protocol.core.ProtocolId;

import static java.lang.foreign.MemoryLayout.*;

/**
 * IPsec Encapsulating Security Payload (ESP) header as defined in RFC 4303.
 * 
 * <p>
 * ESP provides confidentiality (encryption), data origin authentication, data
 * integrity, and anti-replay protection for IP datagrams. Unlike AH, ESP
 * encrypts the payload, making the contents unreadable without the appropriate
 * keys.
 * </p>
 * 
 * <h2>Packet Format</h2>
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 * |                 Security Parameters Index (SPI)               | ^
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 * |                    Sequence Number                            | |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | Auth
 * |                    Initialization Vector (IV)                 | | Coverage
 * |                         (variable, optional)                  | |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 * |                    Payload Data (encrypted)                   | |
 * ~                                                               ~ |
 * |                                                               | |
 * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 * |               |         Padding (0-255 bytes)                 | |
 * +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 * |                               |  Pad Length   | Next Header   | v
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 * |                 Integrity Check Value (ICV)                   |
 * |                         (variable, optional)                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Header vs Trailer</h2>
 * <p>
 * ESP has both a header (SPI + Sequence Number) and a trailer (Padding + Pad
 * Length + Next Header + ICV). The trailer is encrypted (except ICV) and cannot
 * be parsed without decryption. This class only provides access to the
 * unencrypted header portion.
 * </p>
 * 
 * <h2>Encryption and Authentication</h2>
 * <ul>
 * <li><b>Encryption</b> covers: IV + Payload + Padding + Pad Length + Next
 * Header</li>
 * <li><b>Authentication</b> covers: SPI + Sequence + IV + Payload + Padding +
 * Pad Length + Next Header</li>
 * <li><b>ICV</b> is outside both encryption and the authenticated region
 * calculation</li>
 * </ul>
 * 
 * <h2>Common Algorithms</h2>
 * <ul>
 * <li><b>Encryption:</b> AES-CBC, AES-CTR, AES-GCM, ChaCha20-Poly1305</li>
 * <li><b>Authentication:</b> HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512,
 * AES-GMAC</li>
 * <li><b>Combined (AEAD):</b> AES-GCM, ChaCha20-Poly1305</li>
 * </ul>
 * 
 * {@snippet :
 * IpsecEsp esp = packet.getHeader(new IpsecEsp());
 * 
 * System.out.println("SPI: " + Ipsec.spiAsHex(esp.spi()));
 * System.out.println("Sequence: " + esp.sequenceNumber());
 * 
 * // Note: Cannot determine Next Header without decryption
 * // The encrypted payload starts at esp.headerOffset() + 8
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ipsec
 * @see IpsecAh
 * @see <a href="https://tools.ietf.org/html/rfc4303">RFC 4303 - IP
 *      Encapsulating Security Payload</a>
 */
public class IpsecEsp extends FixedHeader implements Detailable {

	/** Protocol HEADER_ID for IPsec ESP. */
	public static final int HEADER_ID = ProtocolId.ESP;

	/** ESP header length in bytes (SPI + Sequence Number only). */
	public static final int HEADER_LENGTH = 8;

	/** ESP header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U32_BE.withName("hdr_spi"),
			U32_BE.withName("hdr_sequence"));

	private static final IntHandle SPI = new IntHandle(LAYOUT, "hdr_spi");
	private static final IntHandle SEQUENCE = new IntHandle(LAYOUT, "hdr_sequence");

	/**
	 * Constructs a new IPsec ESP header.
	 */
	public IpsecEsp() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the Security Parameters Index (32 bits).
	 * 
	 * <p>
	 * The SPI is an arbitrary 32-bit value that, in combination with the
	 * destination IP address and security protocol (ESP), uniquely identifies the
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
	 * <p>
	 * Extended Sequence Numbers (ESN) use a 64-bit counter, where the high 32 bits
	 * are implicit (not transmitted). This field contains only the low 32 bits.
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
	 * Checks if the SPI is in the IANA reserved range.
	 *
	 * @return true if SPI is 0-255
	 */
	public boolean isReservedSpi() {
		return Ipsec.isReservedSpi(spi());
	}

	/**
	 * Returns the offset to the encrypted payload.
	 * 
	 * <p>
	 * The encrypted portion starts immediately after the ESP header (SPI + Sequence
	 * Number). This includes the IV (if any), encrypted payload, padding, pad
	 * length, and next header.
	 * </p>
	 *
	 * @return offset to encrypted payload relative to packet start
	 */
	public long encryptedPayloadOffset() {
		return headerOffset() + HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("IPsec Encapsulating Security Payload", "ESP", HEADER_ID, off, HEADER_LENGTH, h -> {
			h.summaryf("SPI=%s Seq=%d",
					Ipsec.spiAsHex(spi()),
					sequenceNumberUnsigned());

			h.fieldHex("SPI", spi(), 8, intAt(off));
			h.field("Sequence Number", sequenceNumberUnsigned(), intAt(off + 4));

			h.section("Encrypted Payload", "Encrypted", s -> {
				s.field("Offset", encryptedPayloadOffset());
				s.field("Note", "Payload encrypted - cannot parse Next Header without decryption");
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