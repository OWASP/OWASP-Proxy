package org.owasp.proxy.http;

public interface MessageHeader {

	int getId();

	byte[] getHeader();

	String getStartLine() throws MessageFormatException;

	NamedValue[] getHeaders() throws MessageFormatException;

	String getHeader(String name) throws MessageFormatException;

}
