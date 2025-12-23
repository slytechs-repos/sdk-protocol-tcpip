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
import com.slytechs.sdk.protocol.core.FixedHeader;
import com.slytechs.sdk.protocol.core.ProtocolId;
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
 * IpsecEspTrailer trailer = new IpsecEspTrailer();
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
 * @see IpsecEsp
 */
public class IpsecEspTrailer extends FixedHeader implements Detailable {

	/** Protocol HEADER_ID for IPsec ESP Trailer. */
	public static final int HEADER_ID = ProtocolId.ESP_TRAILER;

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

	/**
	 * Constructs a new IPsec ESP Trailer.
	 */
	public IpsecEspTrailer() {
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
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("IPsec ESP Trailer (Decrypted)", "Trailer", HEADER_ID, off, MIN_TRAILER_LENGTH, h -> {
			h.summaryf("PadLen=%d → %s",
					padLength(),
					IpProtocolResolver.resolveAbbrOrNumber(nextHeader()));

			if (padLength() > 0) {
				h.field("Padding", padLength() + " bytes", bits(off - padLength(), padLength()));
			}
			h.field("Pad Length", padLength(), byteAt(off));
			h.field("Next Header", nextHeader(),
					IpProtocolResolver.resolveOrNumber(nextHeader()),
					byteAt(off + 1));
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