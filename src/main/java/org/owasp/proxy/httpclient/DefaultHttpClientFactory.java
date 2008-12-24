package org.owasp.proxy.httpclient;

public class DefaultHttpClientFactory implements HttpClientFactory {

	public HttpClient createHttpClient() {
		return new HttpClient();
	}

}
