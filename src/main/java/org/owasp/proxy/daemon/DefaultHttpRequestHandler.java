package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.SocketAddress;

import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.StreamingRequest;
import org.owasp.proxy.httpclient.StreamingResponse;
import org.owasp.proxy.io.TimingInputStream;

public class DefaultHttpRequestHandler implements HttpRequestHandler {

	private ProxySelector proxySelector = null;

	private ServerGroup serverGroup = null;

	private ThreadLocal<HttpClient> client = new ThreadLocal<HttpClient>() {

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.ThreadLocal#initialValue()
		 */
		@Override
		protected HttpClient initialValue() {
			return createClient();
		}

	};

	public void setServerGroup(ServerGroup serverGroup) {
		this.serverGroup = serverGroup;
	}

	public void setProxySelector(ProxySelector proxySelector) {
		this.proxySelector = proxySelector;
	}

	protected HttpClient createClient() {
		HttpClient client = new HttpClient() {

			/*
			 * (non-Javadoc)
			 * 
			 * @see
			 * org.owasp.httpclient.Client#checkLoop(java.net.SocketAddress)
			 */
			@Override
			protected void validateTarget(SocketAddress target)
					throws IOException {
				if (serverGroup != null && target instanceof InetSocketAddress
						&& serverGroup.wouldAccept((InetSocketAddress) target))
					throw new IOException("Loop detected");
			}

		};
		client.setProxySelector(proxySelector);
		return client;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		client.get().disconnect();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	public StreamingResponse handleRequest(InetAddress source,
			StreamingRequest request, boolean isContinue) throws IOException,
			MessageFormatException {
		HttpClient client = this.client.get();
		if (isContinue) {
			client.sendRequestContent(request.getContent());
		} else {
			client.connect(request.getTarget(), request.isSsl());
			client.sendRequestHeader(request.getHeader());
			if (request.getContent() != null)
				client.sendRequestContent(request.getContent());
		}
		request.setTime(client.getRequestTime());
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(client.getResponseHeader());
		response.setHeaderTime(client.getResponseHeaderEndTime());
		InputStream content = client.getResponseContent();
		if (content != null)
			content = new TimingInputStream(content, response);
		response.setContent(content);
		return response;
	}

}
