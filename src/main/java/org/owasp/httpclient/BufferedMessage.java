package org.owasp.httpclient;

public interface BufferedMessage extends MessageHeader {

	/**
	 * @return
	 */
	byte[] getContent();

}
