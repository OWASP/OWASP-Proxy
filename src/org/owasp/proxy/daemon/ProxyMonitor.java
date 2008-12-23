package org.owasp.proxy.daemon;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

public class ProxyMonitor {

	/**
	 * Called when a request is received by the proxy. Changes can be made to
	 * the Request object to alter what may be sent to the server.
	 * 
	 * @param request
	 *            the Request received from the client
	 * @return a custom Response to be sent directly back to the client without
	 *         making any request to a server, or null to forward the Request
	 * @throws MessageFormatException
	 *             if the request cannot be parsed
	 */
	public Response requestReceived(Request request)
			throws MessageFormatException {
		String connection = request.getHeader("Connection");
		String version = request.getVersion();
		if ("HTTP/1.1".equals(version) && connection != null) {
			String[] headers = connection.split(" *, *");
			for (int i = 0; i < headers.length; i++) {
				request.deleteHeader(headers[i]);
			}
		}
		request.deleteHeader("Proxy-Connection");
		return null;
	}

	/**
	 * Called when an error is encountered while reading the request from the
	 * client.
	 * 
	 * @param request
	 * @param e
	 * @return a customized Response to be sent to the browser, or null to send
	 *         the default error message
	 * @throws MessageFormatException
	 *             if the request couldn't be parsed
	 */
	public Response errorReadingRequest(Request request, Exception e)
			throws MessageFormatException {
		return null;
	}

	/**
	 * Called when the Response headers have been read from the server. The
	 * response content (if any) will not yet have been read. Analysis can be
	 * performed based on the headers to determine whether to intercept the
	 * complete response at a later stage. If you wish to intercept the complete
	 * response message at a later stage, return false from this method to
	 * disable streaming of the response content, otherwise the response would
	 * already have been written to the browser when responseContentReceived is
	 * called.
	 * 
	 * Note: If you modify the response headers in this method, be very careful
	 * not to affect the retrieval of the response content. For example,
	 * deleting a "Transfer-Encoding: chunked" header would be a bad idea!
	 * 
	 * @param conversation
	 * @return true to stream the response to the client as it is being read
	 *         from the server, or false to delay writing the response to the
	 *         client until after responseContentReceived is called
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	public boolean responseHeaderReceived(Conversation conversation)
			throws MessageFormatException {
		return true;
	}

	/**
	 * Called after the Response content has been received from the server. If
	 * streamed is false, the response can be modified here, and the modified
	 * version will be written to the client.
	 * 
	 * @param conversation
	 * @param streamed
	 *            true if the response has already been written to the client
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	public void responseContentReceived(Conversation conversation,
			boolean streamed) throws MessageFormatException {
	}

	/**
	 * Called in the event of an error occurring while reading the response
	 * header from the client
	 * 
	 * @param request
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	public Response errorFetchingResponseHeader(Request request, Exception e)
			throws MessageFormatException {
		return null;
	}

	/**
	 * Called in the event of an error occurring while reading the response
	 * content from the client
	 * 
	 * @param conversation
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	public Response errorFetchingResponseContent(Conversation conversation,
			Exception e) throws MessageFormatException {
		return null;
	}

	public void wroteResponseToBrowser(Conversation conversation)
			throws MessageFormatException {
	}

	public void errorWritingResponseToBrowser(Conversation conversation,
			Exception e) throws MessageFormatException {
	}

}
