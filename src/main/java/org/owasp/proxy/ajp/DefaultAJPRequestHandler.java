package org.owasp.proxy.ajp;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.owasp.proxy.daemon.ServerGroup;
import org.owasp.proxy.http.MessageFormatException;
import org.owasp.proxy.http.StreamingRequest;
import org.owasp.proxy.http.StreamingResponse;
import org.owasp.proxy.http.server.HttpRequestHandler;
import org.owasp.proxy.io.TimingInputStream;

public class DefaultAJPRequestHandler implements AJPRequestHandler,
		HttpRequestHandler {

	private ServerGroup serverGroup = null;

	private InetSocketAddress target;

	private AJPProperties properties = new AJPProperties();

	private ThreadLocal<AJPClient> client = new ThreadLocal<AJPClient>() {

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.ThreadLocal#initialValue()
		 */
		@Override
		protected AJPClient initialValue() {
			return createClient();
		}

	};

	public DefaultAJPRequestHandler() {
	}

	/**
	 * @return the properties
	 */
	public AJPProperties getProperties() {
		return properties;
	}

	/**
	 * @param properties
	 *            the properties to set
	 */
	public void setProperties(AJPProperties properties) {
		this.properties = properties;
	}

	public void setServerGroup(ServerGroup serverGroup) {
		this.serverGroup = serverGroup;
	}

	/**
	 * @return the target
	 */
	public InetSocketAddress getTarget() {
		return target;
	}

	/**
	 * @param target
	 *            the target to set
	 */
	public void setTarget(InetSocketAddress target) {
		this.target = target;
	}

	protected AJPClient createClient() {
		return new AJPClient() {

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
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		client.get().close();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.ajp.AJPRequestHandler#handleRequest(java.net.InetAddress,
	 * org.owasp.ajp.AJPRequest)
	 */
	public StreamingResponse handleRequest(InetAddress source,
			AJPRequest request) throws IOException, MessageFormatException {
		return handleRequest(source, (StreamingRequest) request, false);
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
		AJPClient client = this.client.get();
		client.setProperties(new AJPProperties(properties));

		if (!client.isConnected())
			client.connect(target);

		if (isContinue) {
			throw new RuntimeException("AJP does not support Expect: continue");
		} else {
			StreamingResponse response = client.fetchResponse(request);
			request.setTime(client.getRequestTime());
			response.setHeaderTime(client.getResponseHeaderTime());
			InputStream content = response.getContent();
			if (content != null)
				content = new TimingInputStream(content, response);
			response.setContent(content);
			return response;
		}
	}

}
