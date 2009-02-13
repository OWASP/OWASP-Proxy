package org.owasp.httpclient;

public interface MessageContent {

	void setContent(byte[] content);

	byte[] getContent();

}
