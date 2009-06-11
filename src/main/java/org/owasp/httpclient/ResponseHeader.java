package org.owasp.httpclient;

public interface ResponseHeader extends MessageHeader {

	String getVersion() throws MessageFormatException;

	String getStatus() throws MessageFormatException;

	String getReason() throws MessageFormatException;

}
