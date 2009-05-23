package org.owasp.httpclient;

public interface ReadOnlyMessageHeader {

	int getId();

	byte[] getHeader();

	String getStartLine() throws MessageFormatException;

	NamedValue[] getHeaders() throws MessageFormatException;

	String getHeader(String name) throws MessageFormatException;

}
