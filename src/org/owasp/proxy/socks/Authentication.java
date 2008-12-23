package org.owasp.proxy.socks;

/**
 * The Authentication interface provides for performing method specific
 * authentication for SOCKS5 connections.
 */
public interface Authentication {
	/**
	 * This method is called when SOCKS5 server have selected a particular
	 * authentication method, for which an implementation has been registered.
	 * 
	 * <p>
	 * This method should return an array {inputstream, outputstream}. The reason
	 * for that is that SOCKS5 protocol allows to have method specific
	 * encapsulation of data on the socket for purposes of integrity or
	 * security. And this encapsulation should be performed by those streams
	 * returned from the method.
	 * 
	 * @param methodId
	 *            Authentication method selected by the server.
	 * @param proxySocket
	 *            Socket used to connect to the proxy.
	 * @return Two element array containing Input/Output streams which should be
	 *         used on this connection.
	 */
	Object[] doSocksAuthentication(int methodId, java.net.Socket proxySocket)
			throws java.io.IOException;
}
