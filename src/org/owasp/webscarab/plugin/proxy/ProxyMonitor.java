package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.MessageFormatException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 * Instances of this abstract class registered with a Listener are notified of various events
 * occurring in the Listener, and given an opportunity to modify the behaviour of the
 * Listener, as well as modifying the Requests and Responses observed.
 * 
 * As this class is abstract, one must extend the class, and override the methods of interest. If
 * the methods are not overridden, the Listener behaves exactly as if no ProxyMonitor was set.
 * 
 * @see Listener#setProxyMonitor(ProxyMonitor)
 * 
 * @author rogan
 *
 */
public abstract class ProxyMonitor {

	/**
	 * Called when a request is received by the proxy. Changes can be made
	 * to the Request object to alter what may be sent to the server.
	 * 
	 * @param request the Request received from the client
	 * @return a custom Response to be sent directly back to the client 
	 * without making any request to a server, or null to forward the Request
	 * @throws MessageFormatException TODO
	 */
	public Response requestReceived(Request request) throws MessageFormatException {
		return null;
	}
	
	/**
	 * Called when an error is encountered while reading the request from the client.
	 * 
	 * @param request
	 * @param e
	 * @return a customized Response to be sent to the browser, 
	 * or null to send the default error message
	 * @throws MessageFormatException TODO
	 */
	public Response errorReadingRequest(Request request, Exception e) throws MessageFormatException {
		return null;
	}
	
	/**
	 * Called when the Response headers have been read from the server. The response content (if any)
	 * will not yet have been read. Analysis can be performed based on the headers to determine
	 * whether to intercept the complete response at a later stage. 
	 * 
	 * NB: DO NOT modify the response at this stage! They will be overwritten!
	 * 
	 * @param conversation
	 * @return true to stream the response to the client as it is being read from the server, or false
	 * to delay writing the response to the client until after responseContentReceived is called
	 * @throws MessageFormatException TODO
	 */
	public boolean responseHeaderReceived(Conversation conversation) throws MessageFormatException {
		return true;
	}
	
	/**
	 * Called after the Response content has been received from the server.
	 * If streamed is false, the response can be modified here, and the modified version
	 * will be written to the client.
	 * 
	 * @param conversation
	 * @param streamed true if the response has already been written to the client
	 * @throws MessageFormatException TODO
	 */
	public void responseContentReceived(Conversation conversation, boolean streamed) throws MessageFormatException {}
	
	/**
	 * Called in the event of an error occurring while reading the response header from the client
	 * @param request
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the default
	 * @throws MessageFormatException TODO
	 */
	public Response errorFetchingResponseHeader(Request request, Exception e) throws MessageFormatException {
		return null;
	}
	
	/**
	 * Called in the event of an error occurring while reading the response content from the client
	 * @param conversation
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the default
	 * @throws MessageFormatException TODO
	 */
	public Response errorFetchingResponseContent(Conversation conversation, Exception e) throws MessageFormatException {
		return null;
	}
	
	public void wroteResponseToBrowser(Conversation conversation) throws MessageFormatException {}
	
	public void errorWritingResponseToBrowser(Conversation conversation, Exception e) throws MessageFormatException {}
	
}
