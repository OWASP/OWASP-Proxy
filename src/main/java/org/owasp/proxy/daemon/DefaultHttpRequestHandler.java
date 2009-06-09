package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.owasp.httpclient.Client;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;

public class DefaultHttpRequestHandler implements HttpRequestHandler {

	private ServerGroup serverGroup = null;

	private ThreadLocal<Client> client = new ThreadLocal<Client>() {

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.ThreadLocal#initialValue()
		 */
		@Override
		protected Client initialValue() {
			return createClient();
		}

	};

	public void setServerGroup(ServerGroup serverGroup) {
		this.serverGroup = serverGroup;
	}

	protected Client createClient() {
		return new Client() {

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
		Client client = this.client.get();
		if (isContinue) {
			client.sendRequestContent(request.getContent());
		} else {
			client.connect(request.getTarget(), request.isSsl());
			client.sendRequestHeader(request.getHeader());
			if (request.getContent() != null)
				client.sendRequestContent(request.getContent());
		}
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(client.getResponseHeader());
		response.setContent(client.getResponseContent());
		return response;
	}

}
