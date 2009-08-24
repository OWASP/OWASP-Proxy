package org.owasp.proxy.httpclient;

public interface ResponseHeader extends MessageHeader {

	String getVersion() throws MessageFormatException;

	String getStatus() throws MessageFormatException;

	String getReason() throws MessageFormatException;

	long getHeaderStartedTime();

	long getHeaderCompletedTime();

	long getContentStartedTime();

	long getContentCompletedTime();

}
