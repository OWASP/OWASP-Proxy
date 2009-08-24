package org.owasp.proxy.httpclient;

public interface ResponseHeader extends MessageHeader {

	String getVersion() throws MessageFormatException;

	String getStatus() throws MessageFormatException;

	String getReason() throws MessageFormatException;

	long getHeaderTime();

	long getContentTime();

}
