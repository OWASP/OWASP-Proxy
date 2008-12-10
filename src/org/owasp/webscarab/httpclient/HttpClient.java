package org.owasp.webscarab.httpclient;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.webscarab.io.CopyInputStream;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.MessageFormatException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.URI;

public class HttpClient {

	private SSLContextManager contextManager = null;

	private ProxyManager proxyManager = null;
	
	private Socket socket;
	
	private ByteArrayOutputStream copy = new ByteArrayOutputStream();
	
	private CopyInputStream in = null;
	
	private Conversation conversation = null;
	
	private String host;
	
	private int port;
	
	private String proxyHost;
	
	private int proxyPort;
	
	private boolean ssl;
	
	private boolean direct;
	
	public void setSSLContextManager(SSLContextManager contextManager) {
		this.contextManager = contextManager;
	}

	public void setProxyManager(ProxyManager proxyManager) {
		this.proxyManager = proxyManager;
	}
	
	public Conversation fetchResponse(Request request)
			throws MessageFormatException, IOException {
		if (conversation != null) {
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
		
		URI uri = request.getUri();
		String scheme = uri.getScheme().toLowerCase();
		if (!("http".equals(scheme) || "https".equals(scheme)))
			throw new IOException("Unsupported scheme : " + scheme);

		// establish a socket connection that is connected either to the proxy server
		// or to the server itself. conversation.response will be non-null if the proxy
		// server returned an error
		openConnection(uri, conversation);
		
		if (conversation.getResponse() != null)
			return conversation;
		
		if (socket == null) 
			throw new IOException("Couldn't connect to server!");
		
		if (!socket.isConnected() || socket.isClosed())
			throw new IOException("Socket is not connected");
		
		conversation.setConnection(socket.getLocalSocketAddress().toString() + "->" + socket.getRemoteSocketAddress().toString());
		conversation.setRequest(request);
		
		writeRequest(conversation);
		copy.reset();
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
	}
	
	public void close() throws IOException {
		if (socket != null && !socket.isClosed()) {
			socket.close();
		}
	}
	
	private void openConnection(URI uri, Conversation conversation) throws MessageFormatException, IOException {
		String[] proxies = getProxiesFor(uri);
		
		String host = uri.getHost();
		int port = uri.getPort();
		ssl = "https".equals(uri.getScheme());
		if (port == -1)
			port = (ssl ? 443 : 80);

		if (isConnected(host, port, proxies)) {
			return;
		} else if (socket != null && !socket.isClosed()) {
			try {
				socket.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}
		this.host = host;
		this.port = port;
		
		socket = new Socket();
		socket.setSoTimeout(10000);
		for (String proxy : proxies){
			try {
				if (proxy.equals("DIRECT")) {
					proxyHost = null;
					proxyPort = -1;
					direct = true;
					socket.connect(new InetSocketAddress(host, port), 10000);
					if (ssl)
						layerSsl();
				} else if (proxy.startsWith("PROXY ")) {
					proxy = proxy.substring(6); // "PROXY "
					int c = proxy.indexOf(':');
					if (c == -1)
						throw new IOException("Unparseable proxy '" + proxy + "'");
					proxyHost = proxy.substring(0, c);
					try {
						proxyPort = Integer.parseInt(proxy.substring(c+1));
					} catch (NumberFormatException nfe) {
						IOException ioe = new IOException("Unparseable proxy '" + proxy + "'");
						ioe.initCause(nfe);
						throw ioe;
					}
					socket.connect(new InetSocketAddress(proxyHost, proxyPort), 10000);
					if (ssl) {
						proxyConnect(proxyHost, proxyPort, conversation);
						if (conversation.getResponse() != null) // CONNECT failed!
							return;
						layerSsl();
					}
				} else { // unsupported proxy type!
					continue;
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
				socket.close();
				socket = null;
			}
			if (conversation.getResponse() != null)
				return;
		}
		
	}
	
	private boolean isConnected(String host, int port, String[] proxies) {
		if (socket == null || socket.isClosed() || this.host == null)
			return false;
		return (host.equals(this.host) && port == this.port);
	}
	
	private void layerSsl() throws IOException {
		if (contextManager == null)
			throw new IOException(
					"Context Manager is null, SSL is not supported!");
		SSLContext sslContext = contextManager.getSSLContext(host);
		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) factory.createSocket(socket,
				socket.getInetAddress().getHostName(), socket.getPort(),
				true);
		sslsocket.setUseClientMode(true);
		sslsocket.setSoTimeout(10000);
		socket = sslsocket;
	}
	
	private void proxyConnect(String host, int port, Conversation conversation) throws IOException, MessageFormatException {
		OutputStream out = new BufferedOutputStream(socket.getOutputStream());
		Request request = new Request();
		request.setStartLine("CONNECT " + host + ":" + port + " HTTP/1.0");
		long requestTime = System.currentTimeMillis();
		out.write(request.getMessage());
		out.flush();
		ByteArrayOutputStream copy = new ByteArrayOutputStream();
		CopyInputStream in = new CopyInputStream(socket.getInputStream(), copy);
		while (!"".equals(in.readLine()))
			; // flush the 
		long responseHeaderTime = System.currentTimeMillis();
		Response response = new Response();
		response.setMessage(copy.toByteArray());
		if (!"200".equals(response.getStatus())) {
			conversation.setRequest(request);
			conversation.setRequestTime(requestTime);
			conversation.setResponse(response);
			conversation.setResponseHeaderTime(responseHeaderTime);
			if (Response.flushContent(request.getMethod(), response, in, null)) {
				conversation.setResponseBodyTime(System.currentTimeMillis());
				response.setMessage(copy.toByteArray());
				conversation.setResponse(response);
			}
			socket.close();
			socket = null;
		}
	}
	
	private static final String[] DIRECT = { "DIRECT" };
	
	private String[] getProxiesFor(URI uri) {
		if (proxyManager == null) 
			return DIRECT;
		String proxy = proxyManager.findProxyForUrl(uri);
		if (proxy == null || "".equals(proxy.trim()))
			return DIRECT;
		return proxy.split("[ \t]*;[ \t]*");
	}
	
	private void writeRequest(Conversation conversation) throws MessageFormatException, IOException {
		OutputStream out = new BufferedOutputStream(socket.getOutputStream());

		conversation.setRequestTime(System.currentTimeMillis());
		if (direct) {
			writeDirect(out, conversation.getRequest());
		} else {
			out.write(conversation.getRequest().getMessage());
		}
		out.flush();
	}
	
	private void readResponseHeader() throws MessageFormatException, IOException {
		// read the whole header. Each line gets written into the copy defined
		// above
		while (!"".equals(in.readLine()))
			;

		Response response = new Response();
		response.setMessage(copy.toByteArray());
		if ("100".equals(response.getStatus())) { // 100 Continue, expect another set of headers
			// read the next header
			while (!"".equals(in.readLine()))
				;
			response.setMessage(copy.toByteArray());
		}
		conversation.setResponse(response);
		conversation.setResponseHeaderTime(System.currentTimeMillis());
	}
	
	private void readResponseBody() throws MessageFormatException, IOException {
		Response response = conversation.getResponse();
		if (Response.flushContent(conversation.getRequest().getMethod(), response, in, null)) {
			conversation.setResponseBodyTime(System.currentTimeMillis());
			response.setMessage(copy.toByteArray());
			conversation.setResponse(response);
			copy.reset();
		}
	}

//	private Socket connect(URI uri, String proxy) throws IOException {
//
//		String host = uri.getHost();
//		int port = uri.getPort();
//		boolean ssl = "https".equals(scheme);
//		if (port == -1)
//			port = ( ssl ? 443 : 80);
//
//		Socket socket = new Socket();
//		socket.setSoTimeout(10000);
//		if (proxy == null || "".equals(proxy) || "DIRECT".equalsIgnoreCase(proxy)) {
//			socket.connect(new InetSocketAddress(host, port), 10000);
//		} else {
//			if (proxy.toLowerCase().startsWith("proxy")) { // http proxy
//				String[] parts = proxy.split("[ \t]+");
//				if (parts.length != 2)
//					throw new IOException("Could not connect to proxy '" + proxy + "'");
//				parts = parts[1].split(":");
//				if (parts.length != 2)
//					throw new IOException("Could not connect to proxy '" + proxy + "'");
//				String proxyHost = parts[0];
//				int proxyPort;
//				try {
//					proxyPort = Integer.parseInt(parts[1]);
//				} catch (NumberFormatException nfe) {
//					throw new IOException("Could not connect to proxy '" + proxy + "'", nfe);
//				}
//				socket.connect(new InetSocketAddress(proxyHost, proxyPort), 10000);
//				if (ssl)
//					proxyConnect(socket, host, port);
//			}
//		}
//		
//		if (ssl) {
//		}
//
//		return socket;
//	}

//	private Response proxyConnect(Socket socket, String host, int port) throws IOException, MessageFormatException {
//		OutputStream out = socket.getOutputStream();
//		out.write(("CONNECT " + host + ":" + port + " HTTP/1.0\r\n\r\n").getBytes("ASCII"));
//		ByteArrayOutputStream copy = new ByteArrayOutputStream();
//		InputStream in = new CopyInputStream(socket.getInputStream(), copy);
//		while (!"".equals(readLine(in)))
//			;
//		Response response = new Response();
//		response.setMessage(copy.toByteArray());
//		if (!"200".equals(response.getStatus()))
//			return response;
//		return null;
//	}

	private void writeDirect(OutputStream out, Request request)
			throws MessageFormatException, IOException {
		int baseStart = -1;
		int baseEnd = 0;
		boolean method = true;
		byte[] message = request.getMessage();
		for (int i = 0; i < message.length; i++) {
			if (method && Character.isWhitespace(message[i])) {
				method = false;
			}
			if (!method && !Character.isWhitespace(message[i])
					&& baseStart == -1) {
				baseStart = i;
			}
			if (baseStart > -1 && message[i] == '/') {
				if (baseEnd == -2) {
					baseEnd = i;
					break;
				} else {
					baseEnd--;
				}
			}
			if (message[i] == 0x0d || message[i] == 0x0a)
				throw new MessageFormatException(
						"Encountered CR or LF when parsing the URI!");
		}
		if (baseStart > 0 && baseEnd > baseStart) {
			out.write(message, 0, baseStart);
			out.write(message, baseEnd, message.length - baseEnd);
		} else {
			throw new MessageFormatException("Couldn't parse the URI!");
		}
	}

}
