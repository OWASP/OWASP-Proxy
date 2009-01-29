package org.owasp.proxy.daemon;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

/**
 * ProxyMonitor implementations are notified of major events occurring within
 * ConnectionHandler instances. Specifically, events relating to the lifecycle
 * of requests and responses.
 * 
 * When a request is received from a client, the {@code
 * ProxyMonitor#requestReceived(Request)} method is invoked with the details of
 * the {@code Request}. ProxyMonitor implementations may process the request
 * directly, and return a {@code Response} object containing a response to be
 * returned to the client. In this case, no further calls into the ProxyMonitor
 * will be made for that Request. Alternatively, the implementation may modify
 * the {@code Request} as desired before it is submitted to the server.
 * 
 * If an Exception is thrown while reading the Request from the client, then the
 * {@code ProxyMonitor#errorReadingRequest(Request, Exception)} method will be
 * called. The Request object will contain any bytes which had been read from
 * the Socket before the Exception was thrown. It is possible that no bytes were
 * read. No further ProxyMonitor methods will be called for this Socket
 * connection.
 * 
 * After the Request has been sent to the server, and the {@code Response}
 * headers received, the {@code
 * ProxyMonitor#responseHeaderReceived(Conversation)} method is invoked. This
 * allows implementations to modify the Response headers, and to determine
 * whether they <b>might</b> wish to modify the Response content. If there is a
 * possibility that the ProxyMonitor may wish to modify the Response content,
 * the implementation should return false to disable streaming of the Response
 * content, otherwise the Response content will be streamed directly to the
 * client as it is read from the server. This is good from a performance
 * perspective, as it allows the client/browser to start processing the server
 * response immediately, rather than having to wait for it to be completely
 * buffered by the proxy before being written to the client. Any modification of
 * the Response header in this method must be carefully considered to ensure
 * that the headers and content still match, and can be correctly read by the
 * client. Note that it is possible to modify the Response header, and still
 * return true from this method, if only simple changes are made to the header,
 * e.g. changing the Server: header.
 * 
 * If there is an Exception thrown while writing the Request to the server, or
 * reading the Response headers, the {@code
 * ProxyMonitor#errorFetchingResponseHeader(Request, Exception)} method is
 * called. No further ProxyMonitor methods will be called for this Socket
 * connection.
 * 
 * If the {@link #responseHeaderReceived(Conversation)} method returned false to
 * disable streaming, the {@link #responseContentBuffered(Conversation)} method
 * will be called when the Response content has been completely received from
 * the server. Note that nothing has been written to the client yet at this
 * point, and the entire Response may be modified.
 * 
 * If an Exception is thrown while reading the Response content from the server,
 * the {@link #errorFetchingResponseContent(Conversation, Exception)} method
 * will be invoked.
 * 
 * If the Response was streamed to the client, and there was no Exception thrown
 * <em>reading</em> from the server, the
 * {@link #wroteResponseToBrowser(Conversation)} method will be called. Note
 * that if there is an Exception writing the Response to the client, no error
 * will be raised, and the ProxyMonitor implementation will not be informed.
 * 
 * If the Response was buffered in the proxy before being written to the client,
 * either the {@link #wroteResponseToBrowser(Conversation)} method will be
 * called, or, in the event of an Exception during the write, the
 * {@link #errorWritingResponseToBrowser(Conversation, Exception)} method will
 * be called.
 * 
 * @author rogan
 * 
 */
public interface ProxyMonitor {

	/**
	 * Called when a request is received by the proxy. Changes can be made to
	 * the Request object to alter what may be sent to the server.
	 * 
	 * @param request
	 *            the Request received from the client
	 * @return a custom Response to be sent directly back to the client without
	 *         making any request to a server, or null to forward the Request
	 */
	public Response requestReceived(Request request);

	/**
	 * Called when an error is encountered while reading the request from the
	 * client.
	 * 
	 * @param request
	 * @param e
	 * @return a customized Response to be sent to the browser, or null to send
	 *         the default error message
	 */
	public Response errorReadingRequest(Request request, Exception e);

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
	 */
	public boolean responseHeaderReceived(Conversation conversation);

	/**
	 * Called after the Response content has been received from the server. If
	 * streamed is false, the response can be modified here, and the modified
	 * version will be written to the client.
	 * 
	 * @param conversation
	 */
	public void responseContentBuffered(Conversation conversation);

	/**
	 * Called in the event of an error occurring while reading the response
	 * header from the client
	 * 
	 * @param request
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 */
	public Response errorFetchingResponseHeader(Request request, Exception e);

	/**
	 * Called in the event of an error occurring while reading the response
	 * content from the client
	 * 
	 * @param conversation
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 */
	public Response errorFetchingResponseContent(Conversation conversation,
			Exception e);

	public void wroteResponseToBrowser(Conversation conversation);

	public void errorWritingResponseToBrowser(Conversation conversation,
			Exception e);

	public void conversationCompleted(Conversation conversation);

}