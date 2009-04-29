package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.owasp.httpclient.Client;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;

public class DefaultHttpProxy extends HttpProxy {

	protected ThreadLocal<Client> client = new ThreadLocal<Client>() {

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.ThreadLocal#initialValue()
		 */
		@Override
		protected Client initialValue() {
			return createHttpClient();
		}

	};

	public DefaultHttpProxy(InetSocketAddress listen, InetSocketAddress target,
			SOCKS socks, SSL ssl) throws IOException {
		super(listen, target, socks, ssl);
	}

	protected Client createHttpClient() {
		return new Client();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpProxy#close()
	 */
	@Override
	protected void close() {
		try {
			client.get().disconnect();
		} catch (IOException ignored) {
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @seeorg.owasp.proxy.daemon.HttpProxy#handleRequest(org.owasp.httpclient.
	 * StreamingRequest)
	 */
	@Override
	protected StreamingResponse handleRequest(final InetAddress source,
			final StreamingRequest request) throws IOException {
		Client httpClient = client.get();
		httpClient.connect(request.getTarget(), request.isSsl());
		try {
			httpClient.sendRequestHeader(request.getHeader());
		} catch (MessageFormatException mfe) {
			IOException ioe = new IOException("Error parsing request");
			ioe.initCause(mfe);
			throw ioe;
		}
		if (request.getContent() != null)
			httpClient.sendRequestContent(request.getContent());

		final StreamingResponse response = new StreamingResponse.Impl();
		try {
			response.setHeader(httpClient.getResponseHeader());
		} catch (MessageFormatException mfe) {
			IOException ioe = new IOException("Error parsing response");
			ioe.initCause(mfe);
			throw ioe;
		}
		response.setContent(httpClient.getResponseContent());
		return response;
	}

	public static void main(String[] args) throws Exception {
		InetSocketAddress listen = new InetSocketAddress("localhost", 9998);
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.setSocketTimeout(1000);
		proxy.start();

		System.out.println("Listener started on " + listen);
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();

		proxy.stop();
		System.out.println("Terminated");

	}
}
