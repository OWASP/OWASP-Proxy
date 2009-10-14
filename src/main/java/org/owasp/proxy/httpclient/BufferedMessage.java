package org.owasp.proxy.httpclient;

public interface BufferedMessage extends MessageHeader {

	/**
	 * @return
	 */
	byte[] getContent();

	/**
	 * this method automatically performs any necessary Chunked or Gzip decoding
	 * on the message content required to obtain the actual entity content.
	 * 
	 */
	byte[] getDecodedContent() throws MessageFormatException;

}
