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
package com.slytechs.jnet.protocol.tcpip.ipsec;

import com.slytechs.jnet.protocol.api.ProtocolId;

/**
 * Common constants and utilities for IPsec protocols.
 * 
 * <p>
 * IPsec (Internet Protocol Security) is a suite of protocols that provides
 * security services at the IP layer. It consists of two main protocols:
 * </p>
 * 
 * <ul>
 * <li><b>AH (Authentication Header)</b> - Provides data origin authentication,
 *     data integrity, and optional anti-replay protection. Does not provide
 *     confidentiality (encryption).</li>
 * <li><b>ESP (Encapsulating Security Payload)</b> - Provides confidentiality,
 *     data origin authentication, data integrity, and anti-replay protection.</li>
 * </ul>
 * 
 * <h2>IP Protocol Numbers</h2>
 * <ul>
 * <li>AH - Protocol 51</li>
 * <li>ESP - Protocol 50</li>
 * </ul>
 * 
 * <h2>Security Parameters Index (SPI)</h2>
 * <p>
 * Both AH and ESP use a 32-bit SPI to identify the Security Association (SA)
 * for processing. The SPI, combined with the destination IP address and
 * protocol (AH or ESP), uniquely identifies an SA.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see IpsecAh
 * @see IpsecEsp
 */
public final class Ipsec {
	
	public static final int HEADER_ID = ProtocolId.IPSEC;

	/** IP protocol number for AH (Authentication Header). */
	public static final int IP_PROTOCOL_AH = 51;

	/** IP protocol number for ESP (Encapsulating Security Payload). */
	public static final int IP_PROTOCOL_ESP = 50;

	/** SPI value range reserved by IANA (0x00000000 - 0x000000FF). */
	public static final int SPI_RESERVED_MIN = 0x00000000;

	/** SPI value range reserved by IANA (0x00000000 - 0x000000FF). */
	public static final int SPI_RESERVED_MAX = 0x000000FF;

	/** SPI value indicating no security association. */
	public static final int SPI_NONE = 0;

	private Ipsec() {}

	/**
	 * Checks if an SPI value is in the IANA reserved range.
	 * 
	 * <p>
	 * SPI values 0-255 are reserved by IANA and should not be used for
	 * normal security associations.
	 * </p>
	 *
	 * @param spi the SPI value to check
	 * @return true if SPI is in reserved range (0-255)
	 */
	public static boolean isReservedSpi(int spi) {
		return (spi & 0xFFFFFFFFL) <= SPI_RESERVED_MAX;
	}

	/**
	 * Formats an SPI value as a hexadecimal string.
	 *
	 * @param spi the SPI value
	 * @return SPI in "0x00000000" format
	 */
	public static String spiAsHex(int spi) {
		return "0x%08x".formatted(spi);
	}
}