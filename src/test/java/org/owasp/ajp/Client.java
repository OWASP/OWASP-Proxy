package org.owasp.ajp;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.junit.Test;
import org.owasp.ajp.AJPClient;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.util.MessageUtils;

public class Client {

	private static X509Certificate loadCertificate(InputStream in,
			char[] password) throws GeneralSecurityException, IOException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(in, password);
		Enumeration<String> aliases = ks.aliases();
		String alias = null;
		if (aliases.hasMoreElements())
			alias = aliases.nextElement();
		return (X509Certificate) ks.getCertificate(alias);
	}

	@Test
	// @Ignore
	public void execute() throws Exception {
		InetSocketAddress ajp = new InetSocketAddress("localhost", 8009);
		AJPClient connection = new AJPClient(ajp);
		connection.getRequestAttributes().put("w00t", "WAIT");
		InputStream in = Client.class.getClassLoader().getResourceAsStream(
				"org/owasp/proxy/daemon/server.p12");
		if (in == null) {
			System.err.println("Can't find keystore");
			return;
		}
		X509Certificate cert = loadCertificate(in, "password".toCharArray());
		connection.setSslCert(cert);
		connection.setSslCipher("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
		connection.setSslKeySize("2048");
		connection.setSslSession("SSLSession");

		StreamingRequest request = new StreamingRequest.Impl();
		StreamingResponse response;
		MutableBufferedResponse b;

		InetSocketAddress target = new InetSocketAddress("somehost", 80);
		request.setTarget(target);
		request.setSsl(true);
		request.setMethod("GET");
		request.setResource("/manager/");
		request.setVersion("HTTP/1.0");
		request.setHeader("User-Agent", "AJPClient");

		response = connection.fetchResponse(request);
		b = new MutableBufferedResponse.Impl();
		MessageUtils.buffer(response, b, Integer.MAX_VALUE);
		System.out.println(b);

		// String cookie = response.getHeader("Set-Cookie");
		// int s = cookie.indexOf(';');
		// cookie = cookie.substring(0, s);
		// int e = cookie.indexOf('=');
		// cookie = cookie.substring(e);
		//
		// String content = "browser=test&sequence=0";
		// request.setMethod("POST");
		// request.setResource("/cachetest/EntryServlet?action=register");
		// request.setVersion("HTTP/1.0");
		// request.setHeader("Content-Type",
		// "application/x-www-form-urlencoded");
		// request.setHeader("Cookie", cookie);
		// request.setHeader("Content-Length",
		// Integer.toString(content.length()));
		// request.setHeader("User-Agent", "AJPClient");
		// request.setContent(new ByteArrayInputStream(AsciiString
		// .getBytes(content)));
		//
		// response = connection.fetchResponse(request);
		// b = new MutableBufferedResponse.Impl();
		// MessageUtils.buffer(response, b, Integer.MAX_VALUE);
		// System.out.println(b);
		//
		// request.setMethod("GET");
		// request.setResource("/cachetest/EntryServlet?sequence=4000");
		// request.deleteHeader("Content-Length");
		// request.deleteHeader("Content-Type");
		// request.setContent(null);
		//
		// // connection.setSecure(true);
		//
		// response = connection.fetchResponse(request);
		// b = new MutableBufferedResponse.Impl();
		// MessageUtils.buffer(response, b, Integer.MAX_VALUE);
		// System.out.println(b);
		//
		connection.close();

	}
}
