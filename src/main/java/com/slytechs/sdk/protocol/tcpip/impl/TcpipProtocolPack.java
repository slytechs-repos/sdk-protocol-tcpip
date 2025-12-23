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
package com.slytechs.sdk.protocol.tcpip.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import com.slytechs.sdk.protocol.core.Header;
import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.pack.AbstractProtocolPack;
import com.slytechs.sdk.protocol.core.pack.ProtocolPack;
import com.slytechs.sdk.protocol.tcpip.Tcpip;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class TcpipProtocolPack extends AbstractProtocolPack {

	private static final AtomicReference<TcpipProtocolPack> SINGLETON = new AtomicReference<>();

	public static final int ID = ProtocolPack.TCPIP_ID;
	public static final String NAME = "tcpip";
	public static final String DESCRIPTION = "Common TCP/IP protocol pack";
	private static final Map<Integer, Protocol> protocolMap = new HashMap<>();
	private static final List<Protocol> protocolList;

	static {
		Arrays.stream(Tcpip.values())
				.forEach(p -> protocolMap.put(p.id() & ProtocolId.MASK_DESCRIPTOR, p));

		protocolList = Collections.unmodifiableList(List.copyOf(protocolMap.values()));
	}

	public static TcpipProtocolPack get() {
		if (SINGLETON.get() == null)
			SINGLETON.compareAndSet(null, new TcpipProtocolPack());

		return SINGLETON.get();
	}

	/**
	 * @param id
	 * @param name
	 * @param description
	 */
	private TcpipProtocolPack() {
		super(ID, NAME, DESCRIPTION);

		loaded.set(true);
	}

	/**
	 * @see com.slytechs.jnet.proto.api.pack.ProtocolPack#listProtocols()
	 */
	@Override
	public List<Protocol> listProtocols() {
		return protocolList;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.pack.ProtocolPack#mapProtocolUsingId(int)
	 */
	@Override
	public Protocol mapProtocolUsingId(int protocolId) {
		return protocolMap.get(protocolId);
	}

	/**
	 * @see com.slytechs.jnet.proto.api.pack.ProtocolPack#findProtocol(java.lang.Class)
	 */
	@Override
	public Optional<Protocol> findProtocol(Class<? extends Header> headerClass) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
