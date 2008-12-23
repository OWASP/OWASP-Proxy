/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
package org.owasp.proxy.httpclient;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.daemon.Listener;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

public class HttpClient {

	public static final ProxySelector NO_PROXY = new ProxySelector() {
		@Override
		public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
		}

		@Override
		public List<Proxy> select(URI uri) {
			return Arrays.asList(Proxy.NO_PROXY);
		}
	};
	
	private SSLContextManager contextManager = new SSLContextManager();

	private ProxySelector proxySelector = null;
	
	private Socket socket;
	
	private InetSocketAddress target = null;
	
	private boolean direct = true;
	
	private ByteArrayOutputStream copy = null;
	
	private CopyInputStream in = null;
	
	private Conversation conversation = null;
	
	private Resolver resolver;
	
	public void setSSLContextManager(SSLContextManager contextManager) {
		this.contextManager = contextManager;
	}

	public void setProxySelector(ProxySelector proxySelector) {
		this.proxySelector = proxySelector;
	}
	
	public void setResolver(Resolver resolver) {
		this.resolver = resolver;
	}
	
	public Conversation fetchResponse(Request request)
			throws MessageFormatException, IOException {
		// try to clean up any previous conversations
		if (in != null && conversation != null) {
			try {
				fetchResponseContent(null);
			} catch (MessageFormatException mfe) {
				close();
			} catch (IOException ioe) {
				close();
			}
		}
		fetchResponseHeader(request);
		readResponseBody();
		Conversation conversation = this.conversation;
		this.conversation = null;
		return conversation;
	}
	
	public Conversation fetchResponseHeader(Request request)
		throws MessageFormatException, IOException {
		conversation = new Conversation();
		conversation.setRequest(request);
		
		// establish a socket connection that is connected either to the proxy server
		// or to the server itself. conversation.response will be non-null if the proxy
		// server returned an error
		// instance variable "direct" is set to false if we connect through a non-SSL http proxy
		openConnection(conversation);
		
		if (conversation.getResponse() != null)
			return conversation;
		
		if (socket == null) 
			throw new IOException("Couldn't connect to server!");
		
		if (!socket.isConnected() || socket.isClosed())
			throw new IOException("Socket is not connected");
		
		conversation.setConnection(socket.getLocalSocketAddress().toString() + "->" + socket.getRemoteSocketAddress().toString());
		conversation.setRequest(request);
		
		writeRequest(conversation);
		copy = new ByteArrayOutputStream();
		in = new CopyInputStream(socket.getInputStream(), copy);
		readResponseHeader();
		
		return conversation;
	}
	
	public void fetchResponseContent(OutputStream out) throws MessageFormatException, IOException {
		if (conversation == null)
			throw new IllegalStateException("fetchResponseContent called without fetchResponseHeader");
		if (out != null)
			in = new CopyInputStream(socket.getInputStream(), new OutputStream[] { copy, out });
		readResponseBody();
		String version = conversation.getResponse().getVersion();
		boolean close = "HTTP/1.0".equals(version); // default to close
		String connection = conversation.getResponse().getHeader("Connection");
		if (connection != null)
			close = "close".equalsIgnoreCase(connection);
		if (close)
			close();
	}
	
	public void close() throws IOException {
		if (socket != null && !socket.isClosed()) {
			socket.close();
			in = null;
			copy = null;
		}
	}
	
	private URI constructUri(boolean ssl, String host, int port) {
		StringBuilder buff = new StringBuilder();
		buff.append(ssl ? "https" : "http").append("://").append(host).append(":").append(port);
		return URI.create(buff.toString());
	}
	
	private void checkLoop(SocketAddress dest) throws IOException {
		// FIXME - this is looking a bit clunky
		SocketAddress[] listeners = Listener.getListeners();
		if (dest instanceof InetSocketAddress) {
			InetSocketAddress dst = (InetSocketAddress) dest;
			for (int i=0; i<listeners.length; i++) {
				if (listeners[i] instanceof InetSocketAddress) {
					InetSocketAddress isa = (InetSocketAddress) listeners[i];
					if (isa.getAddress().isAnyLocalAddress()) {
						if (NetworkInterface.getByInetAddress(dst.getAddress()) != null && 
								dst.getPort() == isa.getPort())
								throw new IOException("Loop detected! Request target is a local Listener");
					} else if (dest.equals(listeners[i]))
						throw new IOException("Loop detected! Request target is a local Listener");
				}
			}
		}
	}
	
	private void openConnection(Conversation conversation) throws MessageFormatException, IOException {
		Request request = conversation.getRequest();
		boolean ssl = request.isSsl();
		String host = request.getHost();
		if (host == null)
			throw new MessageFormatException("Host is not set, don't know where to connect to!");
		int port = request.getPort();
		
		if (port == -1)
			port = (ssl ? 443 : 80);
		
		InetSocketAddress target = null;
		if (resolver != null) {
			target = new InetSocketAddress(resolver.getAddress(host), port);
		} else {
			target = new InetSocketAddress(host, port);
		}
		
		URI uri = constructUri(ssl, host, port);
		List<Proxy> proxies = getProxySelector().select(uri);
		
		if (isConnected(target)) {
			return;
		} else if (socket != null && !socket.isClosed()) {
			try {
				socket.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}
		
		socket = null;
		IOException lastAttempt = null;
		for (Proxy proxy : proxies) {
			direct = true;
			try {
				SocketAddress addr = proxy.address();
				checkLoop(addr);
				if (proxy.type() == Proxy.Type.HTTP) {
					socket = new Socket(Proxy.NO_PROXY);
					socket.setSoTimeout(10000);
					socket.connect(addr);
					if (ssl) {
						proxyConnect(target, conversation);
						if (conversation.getResponse() != null) // CONNECT failed!
							return;
						layerSsl(target);
					} else 
						direct = false;
				} else {
					socket = new Socket(proxy);
					socket.setSoTimeout(10000);
					socket.connect(target);
					if (ssl)
						layerSsl(target);
				}
			} catch (IOException ioe) {
				getProxySelector().connectFailed(uri, target, ioe);
				lastAttempt = ioe;
				socket.close();
				socket = null;
			}
			if (conversation.getResponse() != null)
				return;
			if (socket != null && socket.isConnected()) {
				// success
				return;
			}
		}
		if (lastAttempt != null)
			throw lastAttempt;
		throw new IOException("Couldn't connect to server");
	}
	
	private boolean isConnected(InetSocketAddress target) {
		if (socket == null || socket.isClosed() || socket.isInputShutdown())
			return false;
		if (target.equals(this.target)) {
			try {
				// FIXME: This only works because we don't implement pipelining!
	            int oldtimeout = socket.getSoTimeout();
	            try {
	                socket.setSoTimeout(1);
	                byte[] buff = new byte[1024];
	                int got = socket.getInputStream().read(buff);
	                if (got == -1)
	                	return false;
	                if (got > 0) {
	                	System.err.println("Unexpected data read from socket:\n\n" + new String(buff, 0, got));
	                	return false;
	                }
	            } catch (SocketTimeoutException e) {
	            	return true;
	            } finally {
	                socket.setSoTimeout(oldtimeout);
	            }
			} catch (IOException ioe) {
				System.err.println("Looks closed!");
				return false;
			}
		}
		return false;
	}
	
	private void layerSsl(InetSocketAddress target) throws IOException {
		if (contextManager == null)
			throw new IOException(
					"Context Manager is null, SSL is not supported!");
		SSLContext sslContext = contextManager.getSSLContext(target.getHostName());
		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) factory.createSocket(socket,
				socket.getInetAddress().getHostName(), socket.getPort(),
				true);
		sslsocket.setUseClientMode(true);
		sslsocket.setSoTimeout(10000);
		sslsocket.startHandshake();
		socket = sslsocket;
	}
	
	private void proxyConnect(InetSocketAddress target, Conversation conversation) throws IOException, MessageFormatException {
		OutputStream out = new BufferedOutputStream(socket.getOutputStream());
		Request request = new Request();
		request.setStartLine("CONNECT " + target.getHostName() + ":" + target.getPort() + " HTTP/1.0");
		long requestTime = System.currentTimeMillis();
		out.write(request.getMessage());
		out.flush();
		ByteArrayOutputStream copy = new ByteArrayOutputStream();
		CopyInputStream in = new CopyInputStream(socket.getInputStream(), copy);
		while (!"".equals(in.readLine()))
			; // flush the response headers
		
		long responseHeaderTime = System.currentTimeMillis();
		Response response = new Response();
		response.setMessage(copy.toByteArray());
		if (!"200".equals(response.getStatus())) {
			conversation.setRequest(request);
			conversation.setRequestTime(requestTime);
			conversation.setResponse(response);
			conversation.setResponseHeaderTime(responseHeaderTime);
			if (Response.flushContent(request.getMethod(), response, in)) {
				conversation.setResponseBodyTime(System.currentTimeMillis());
				response.setMessage(copy.toByteArray());
				conversation.setResponse(response);
			}
			socket.close();
			socket = null;
		}
	}
	
	private ProxySelector getProxySelector() {
		if (proxySelector == null) 
			return NO_PROXY;
		return proxySelector;
	}
	
	private void writeRequest(Conversation conversation) throws MessageFormatException, IOException {
		OutputStream out = new BufferedOutputStream(socket.getOutputStream());

		conversation.setRequestTime(System.currentTimeMillis());
		if (!direct) {
			writeProxy(out, conversation.getRequest());
		} else {
			out.write(conversation.getRequest().getMessage());
		}
		out.flush();
	}
	
	private void readResponseHeader() throws MessageFormatException, IOException {
		// read the whole header. Each line gets written into the copy defined
		// above
		String line;
		do {
			line = in.readLine();
		} while (line != null && !"".equals(line));

		if (line == null) {
			throw new IOException("Unexpected end of stream reading response header");
		}
		
		Response response = new Response();
		response.setMessage(copy.toByteArray());

		if ("100".equals(response.getStatus())) { // 100 Continue, expect another set of headers
			// read the next header
			while (!"".equals(in.readLine()))
				System.err.println("'");
			response.setMessage(copy.toByteArray());
		}

		conversation.setResponse(response);
		conversation.setResponseHeaderTime(System.currentTimeMillis());
	}
	
	private void readResponseBody() throws MessageFormatException, IOException {
		copy.reset();
		Response response = conversation.getResponse();
		if (Response.flushContent(conversation.getRequest().getMethod(), response, in)) {
			conversation.setResponseBodyTime(System.currentTimeMillis());
			response.setContent(copy.toByteArray());
			conversation.setResponse(response);
			copy.reset();
		}
		// allow the copy ByteArrayOutputStream to be GC'd 
		copy = null;
		in = null;
	}

	private void writeProxy(OutputStream out, Request request)
			throws MessageFormatException, IOException {
		int resourceStart = -1;
		boolean method = true;
		byte[] message = request.getMessage();
		for (int i = 0; i < message.length; i++) {
			if (method && Character.isWhitespace(message[i])) {
				method = false;
			}
			if (!method && !Character.isWhitespace(message[i])
					&& resourceStart == -1) {
				resourceStart = i;
				break;
			}
			if (message[i] == 0x0d || message[i] == 0x0a)
				throw new MessageFormatException(
						"Encountered CR or LF when parsing the URI!");
		}
		if (resourceStart > 0) {
			BufferedOutputStream bos = new BufferedOutputStream(out);
			bos.write(message, 0, resourceStart);
			bos.write(constructUri(request.isSsl(), request.getHost(), request.getPort()).toString().getBytes());
			bos.write(message, resourceStart, message.length - resourceStart);
			bos.flush();
		} else {
			throw new MessageFormatException("Couldn't parse the URI!");
		}
	}

}
