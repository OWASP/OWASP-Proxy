package org.owasp.httpclient;

import java.net.InetSocketAddress;

public interface ReadOnlyRequestHeader extends ReadOnlyMessageHeader {

	InetSocketAddress getTarget();

	boolean isSsl();

	String getMethod() throws MessageFormatException;

	String getResource() throws MessageFormatException;

	String getVersion() throws MessageFormatException;

}
