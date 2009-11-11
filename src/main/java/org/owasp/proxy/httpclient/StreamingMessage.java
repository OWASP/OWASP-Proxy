package org.owasp.proxy.httpclient;

import java.io.InputStream;

public interface StreamingMessage extends MutableMessageHeader {

	InputStream getContent();

	InputStream getDecodedContent() throws MessageFormatException;

	void setContent(InputStream content);

	void setDecodedContent(InputStream content) throws MessageFormatException;

}
