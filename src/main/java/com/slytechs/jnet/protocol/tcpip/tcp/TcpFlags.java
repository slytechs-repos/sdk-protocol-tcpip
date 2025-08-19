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
package com.slytechs.jnet.protocol.tcpip.tcp;

import java.util.Arrays;
import java.util.Collection;

import com.slytechs.jnet.protocol.api.flag.AbstractFlagSet;

/**
 * TCP flags container that manages the 9-bit control flags field.
 */
public class TcpFlags extends AbstractFlagSet<TcpFlag> {
    private static final Collection<TcpFlag> ALL_FLAGS = Arrays.asList(TcpFlag.values());
    
    public TcpFlags(long value) {
        super(value & 0x1FF, ALL_FLAGS); // Only use lower 9 bits
    }
    
    public TcpFlags() {
        this(0);
    }
    
    @Override
    public TcpFlags withValue(long value) {
        return new TcpFlags(value);
    }
    
    // Individual flag test methods
    public boolean isFin() { return isSet(TcpFlag.FIN); }
    public boolean isSyn() { return isSet(TcpFlag.SYN); }
    public boolean isRst() { return isSet(TcpFlag.RST); }
    public boolean isPsh() { return isSet(TcpFlag.PSH); }
    public boolean isAck() { return isSet(TcpFlag.ACK); }
    public boolean isUrg() { return isSet(TcpFlag.URG); }
    public boolean isEce() { return isSet(TcpFlag.ECE); }
    public boolean isCwr() { return isSet(TcpFlag.CWR); }
    public boolean isNs() { return isSet(TcpFlag.NS); }
    
    // Individual flag set methods
    public TcpFlags setFin() { return (TcpFlags) withFlag(TcpFlag.FIN); }
    public TcpFlags setSyn() { return (TcpFlags) withFlag(TcpFlag.SYN); }
    public TcpFlags setRst() { return (TcpFlags) withFlag(TcpFlag.RST); }
    public TcpFlags setPsh() { return (TcpFlags) withFlag(TcpFlag.PSH); }
    public TcpFlags setAck() { return (TcpFlags) withFlag(TcpFlag.ACK); }
    public TcpFlags setUrg() { return (TcpFlags) withFlag(TcpFlag.URG); }
    public TcpFlags setEce() { return (TcpFlags) withFlag(TcpFlag.ECE); }
    public TcpFlags setCwr() { return (TcpFlags) withFlag(TcpFlag.CWR); }
    public TcpFlags setNs() { return (TcpFlags) withFlag(TcpFlag.NS); }
    
    // Individual flag clear methods
    public TcpFlags clearFin() { return (TcpFlags) withoutFlag(TcpFlag.FIN); }
    public TcpFlags clearSyn() { return (TcpFlags) withoutFlag(TcpFlag.SYN); }
    public TcpFlags clearRst() { return (TcpFlags) withoutFlag(TcpFlag.RST); }
    public TcpFlags clearPsh() { return (TcpFlags) withoutFlag(TcpFlag.PSH); }
    public TcpFlags clearAck() { return (TcpFlags) withoutFlag(TcpFlag.ACK); }
    public TcpFlags clearUrg() { return (TcpFlags) withoutFlag(TcpFlag.URG); }
    public TcpFlags clearEce() { return (TcpFlags) withoutFlag(TcpFlag.ECE); }
    public TcpFlags clearCwr() { return (TcpFlags) withoutFlag(TcpFlag.CWR); }
    public TcpFlags clearNs() { return (TcpFlags) withoutFlag(TcpFlag.NS); }
    
    // Connection state methods
    public boolean isConnectionRequest() {
        return isSyn() && !isAck();
    }
    
    public boolean isConnectionResponse() {
        return isSyn() && isAck();
    }
    
    public boolean isConnectionEstablished() {
        return isAck() && !isSyn() && !isFin() && !isRst();
    }
    
    public boolean isConnectionClose() {
        return isFin();
    }
    
    public boolean isConnectionReset() {
        return isRst();
    }
    
    public boolean hasData() {
        return isPsh() || isFin();
    }
    
    public boolean isKeepAlive() {
        return isAck() && !isSyn() && !isFin() && !isRst() && !isPsh() && !isUrg();
    }
    
    // ECN (Explicit Congestion Notification) methods
    public boolean isEcnCapable() {
        return isEce() || isCwr();
    }
    
    public boolean isEcnEcho() {
        return isEce();
    }
    
    public boolean isCongestionWindowReduced() {
        return isCwr();
    }
    
    // Factory methods for common flag combinations
    public static TcpFlags synPacket() {
        return new TcpFlags().setSyn();
    }
    
    public static TcpFlags synAckPacket() {
        return new TcpFlags().setSyn().setAck();
    }
    
    public static TcpFlags ackPacket() {
        return new TcpFlags().setAck();
    }
    
    public static TcpFlags finPacket() {
        return new TcpFlags().setFin().setAck();
    }
    
    public static TcpFlags finAckPacket() {
        return new TcpFlags().setFin().setAck();
    }
    
    public static TcpFlags rstPacket() {
        return new TcpFlags().setRst();
    }
    
    public static TcpFlags rstAckPacket() {
        return new TcpFlags().setRst().setAck();
    }
    
    public static TcpFlags dataPacket() {
        return new TcpFlags().setAck().setPsh();
    }
    
    public static TcpFlags keepAlivePacket() {
        return new TcpFlags().setAck();
    }
    
    /**
     * Returns a description of the connection state based on flags.
     */
    public String getConnectionState() {
        if (isConnectionRequest()) return "SYN_SENT";
        if (isConnectionResponse()) return "SYN_RECEIVED";
        if (isConnectionClose()) return "FIN_WAIT";
        if (isConnectionReset()) return "RESET";
        if (isConnectionEstablished()) return "ESTABLISHED";
        if (value() == 0) return "CLOSED";
        return "UNKNOWN";
    }
    
    /**
     * Returns the standard TCP flag string representation (e.g., "S" for SYN, "A" for ACK).
     */
    public String toFlagString() {
        StringBuilder sb = new StringBuilder();
        if (isNs()) sb.append("N");
        if (isCwr()) sb.append("C");
        if (isEce()) sb.append("E");
        if (isUrg()) sb.append("U");
        if (isAck()) sb.append("A");
        if (isPsh()) sb.append("P");
        if (isRst()) sb.append("R");
        if (isSyn()) sb.append("S");
        if (isFin()) sb.append("F");
        return sb.length() > 0 ? sb.toString() : "-";
    }
    
    @Override
    public String toString() {
        return toFlagString() + " (" + getConnectionState() + ")";
    }
}