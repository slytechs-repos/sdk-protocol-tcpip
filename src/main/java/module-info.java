
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
/**
 * 
 */
module com.slytechs.jnet.protocol.tcpip {

	exports com.slytechs.jnet.protocol.tcpip;
	exports com.slytechs.jnet.protocol.tcpip.ethernet;
	exports com.slytechs.jnet.protocol.tcpip.ip;
	exports com.slytechs.jnet.protocol.tcpip.tcp;

	requires com.slytechs.jnet.core.api;
	requires transitive com.slytechs.jnet.protocol.api;
	requires java.logging;

	provides com.slytechs.jnet.protocol.api.pack.ProtocolPackPlugin
			with com.slytechs.jnet.protocol.tcpip.impl.TcpipPlugin;
	provides com.slytechs.jnet.protocol.api.table.TableProvider
			with com.slytechs.jnet.protocol.tcpip.table.TcpIpTableProvider;
	
	provides com.slytechs.jnet.protocol.api.spi.ProtocolProvider
			with com.slytechs.jnet.protocol.tcpip.impl.TcpipProtocolProvider;

}