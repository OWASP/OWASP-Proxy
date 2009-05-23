package org.owasp.httpclient;

public interface ReadOnlyResponseHeader extends ReadOnlyMessageHeader {

	String getVersion() throws MessageFormatException;

	String getStatus() throws MessageFormatException;

	String getReason() throws MessageFormatException;

}
