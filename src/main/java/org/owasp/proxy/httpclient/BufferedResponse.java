package org.owasp.proxy.httpclient;

public interface BufferedResponse extends ResponseHeader, BufferedMessage {

	byte[] getDecodedContent() throws MessageFormatException;

}
