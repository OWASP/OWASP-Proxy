package org.owasp.httpclient;

import java.io.InputStream;

public interface StreamingMessage extends MessageHeader {

	InputStream getContent();

	void setContent(InputStream content);

}
