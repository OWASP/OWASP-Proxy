package org.owasp.proxy.http;

public interface BufferedResponse extends ResponseHeader, BufferedMessage {

	byte[] getDecodedContent() throws MessageFormatException;

}
