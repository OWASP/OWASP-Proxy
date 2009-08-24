package org.owasp.proxy.httpclient;

public interface BufferedMessage extends MessageHeader {

	/**
	 * @return
	 */
	byte[] getContent();

}
