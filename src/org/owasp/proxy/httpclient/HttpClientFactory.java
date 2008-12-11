package org.owasp.proxy.httpclient;

/*
 * Creates pre-configured HttpClient objects, set up with any
 * SSLContext
 */
public class HttpClientFactory {

	public HttpClient getHttpClient() {
		HttpClient client = new HttpClient();
		return client;
	}
}
