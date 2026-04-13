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

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.text.DataEmitter;
import com.slytechs.sdk.protocol.core.header.FixedHeader;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;
import com.slytechs.sdk.protocol.tcpip.ip.IpProtocolResolver;

import static java.lang.foreign.MemoryLayout.*;

/**
 * IPsec ESP Trailer (decrypted) as defined in RFC 4303.
 * 
 * <p>
 * The ESP trailer appears at the end of the decrypted ESP payload and contains
 * the padding, pad length, and next header fields. This class is used after ESP
 * decryption to parse the trailer fields.
 * </p>
 * 
 * <h2>Trailer Format</h2>
 * 
 * <pre>
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Payload Data (decrypted)                   |
 * ~                                                               ~
 * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               |         Padding (0-255 bytes)                 |
 * +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |  Pad Length   | Next Header   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Usage</h2>
 * <p>
 * This class is typically used after decrypting an ESP payload. The trailer is
 * located at the end of the decrypted data, before any ICV.
 * </p>
 * 
 * {@snippet :
 * // After decryption, bind trailer to end of decrypted payload
 * EspTrailer trailer = new EspTrailer();
 * trailer.bind(decryptedData, trailerOffset, 2);  // Min 2 bytes
 * 
 * int padLen = trailer.padLength();
 * int nextHeader = trailer.nextHeader();
 * 
 * // Actual payload ends at: trailerOffset - padLen
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Esp
 */
public class EspTrailer extends FixedHeader {

	/** Protocol HEADER_ID for IPsec ESP Trailer. */
	public static final int HEADER_ID = ProtocolIds.ESP_TRAILER;

	/** Minimum trailer length (Pad Length + Next Header only). */
	public static final int MIN_TRAILER_LENGTH = 2;

	/** Maximum trailer length (255 bytes padding + 2 bytes). */
	public static final int MAX_TRAILER_LENGTH = 257;

	/** ESP Trailer memory layout (fixed portion at end). */
	public static final MemoryLayout LAYOUT = structLayout(
			U8_BE.withName("trl_pad_length"),
			U8_BE.withName("trl_next_header"));

	private static final ByteHandle PAD_LENGTH = new ByteHandle(LAYOUT, "trl_pad_length");
	private static final ByteHandle NEXT_HEADER = new ByteHandle(LAYOUT, "trl_next_header");

	// @formatter:off
	private static final String SUMMARY =
			"IPsec ESP Trailer (Decrypted), PadLen: {espt.padlen}, Next: {espt.nxt}";

	private static final DataEmitter<EspTrailer> ESP_TRAILER_EMITTER;
	static {
		ESP_TRAILER_EMITTER = new DataEmitter<>();

		ESP_TRAILER_EMITTER.section(SUMMARY, sec -> sec
				.delegate((e, t, c) -> {
					if (t.padLength() > 0)
						e.field("Padding", "%d bytes".formatted(t.padLength()));
					return e;
				})
				.field("Pad Length", EspTrailer::padLength, "espt.padlen")
				.field("Next Header", t -> "%s (%d)".formatted(
						IpProtocolResolver.resolveOrNumber(t.nextHeader()),
						t.nextHeader()), "espt.nxt"));
	}
	// @formatter:on
	/**
	 * Constructs a new IPsec ESP Trailer.
	 */
	public EspTrailer() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the Pad Length field (8 bits).
	 * 
	 * <p>
	 * Indicates the number of padding bytes preceding this field. Padding is used
	 * to align the encrypted data to the cipher block size and to ensure the Pad
	 * Length and Next Header fields are right-aligned.
	 * </p>
	 *
	 * @return the padding length (0-255)
	 */
	public int padLength() {
		return PAD_LENGTH.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Pad Length field.
	 *
	 * @param padLength the padding length (0-255)
	 */
	public void setPadLength(int padLength) {
		PAD_LENGTH.setByte(view(), 0, (byte) padLength);
	}

	/**
	 * Returns the Next Header field (8 bits).
	 * 
	 * <p>
	 * Identifies the type of the payload data. Uses the same values as the IPv4
	 * Protocol or IPv6 Next Header fields.
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
	 * Returns the total trailer length including padding.
	 *
	 * @return padding length + 2 (for Pad Length and Next Header fields)
	 */
	public int trailerLength() {
		return padLength() + MIN_TRAILER_LENGTH;
	}

	/**
	 * @see com.slytechs.sdk.common.text.Textual#dataEmitter()
	 */
	@Override
	public DataEmitter<?> dataEmitter() {
		return ESP_TRAILER_EMITTER;
	}
}