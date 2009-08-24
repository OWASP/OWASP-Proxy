package org.owasp.proxy.httpclient;

import java.io.InputStream;

public interface StreamingMessage extends MutableMessageHeader {

	InputStream getContent();

	void setContent(InputStream content);

}
