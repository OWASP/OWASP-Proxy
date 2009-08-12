package org.owasp.ajp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MutableResponseHeader;
import org.owasp.httpclient.NamedValue;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.util.Base64;

public class AJPClient {

	private static final String START_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";

	private static final String END_CERTIFICATE = "\n-----END CERTIFICATE-----\n";

	private enum State {
		IDLE, ASSIGNED
	}

	private Socket sock;

	private InputStream in;

	private OutputStream out;

	private State state;

	private AJPMessage ajpRequest, ajpResponse;

	private String remoteAddress, remoteHost, context, servletPath, remoteUser,
			authType, route, sslCert, sslCipher, sslSession, sslKeySize,
			secret, storedMethod;

	private Map<String, String> requestAttributes = null;

	public AJPClient(InetSocketAddress target) throws IOException {
		this(Proxy.NO_PROXY, target);
	}

	public AJPClient(Proxy proxy, InetSocketAddress target)
			throws IOException {
		sock = new Socket(proxy);
		sock.connect(target);
		in = sock.getInputStream();
		out = sock.getOutputStream();
		state = State.IDLE;
		ajpRequest = new AJPMessage(8192);
		ajpResponse = new AJPMessage(8192);
	}

	public void close() throws IOException {
		sock.close();
	}

	public StreamingResponse fetchResponse(StreamingRequest request)
			throws MessageFormatException, IOException {
		if (!State.IDLE.equals(state))
			throw new IllegalStateException(
					"Can't fetch another response while one is in progress");
		translate(request, ajpRequest);
		out.write(ajpRequest.getBuffer(), 0, ajpRequest.getLen());
		InputStream content = request.getContent();
		if (request.getContent() != null) {
			ajpRequest.reset();
			ajpRequest.appendBytes(content, Integer.MAX_VALUE);
			ajpRequest.end(AJPMessage.AJP_CLIENT);
			out.write(ajpRequest.getBuffer(), 0, ajpRequest.getLen());
		}
		out.flush();

		readMessage(in, ajpResponse);

		byte type = ajpResponse.peekByte();

		while (type == AJPConstants.JK_AJP13_GET_BODY_CHUNK) {
			ajpResponse.getByte(); // get the type
			int max = ajpResponse.getInt();
			ajpRequest.reset();
			ajpRequest.appendBytes(content, max);
			ajpRequest.end(AJPMessage.AJP_CLIENT);
			out.write(ajpRequest.getBuffer(), 0, ajpRequest.getLen());
			out.flush();
			readMessage(in, ajpResponse);
			type = ajpResponse.peekByte();
		}

		StreamingResponse response = new StreamingResponse.Impl();
		if (type == AJPConstants.JK_AJP13_SEND_HEADERS) {
			translate(ajpResponse, response);
		} else
			throw new IllegalStateException(
					"Expected message of type SEND_HEADERS, got " + type);

		response.setContent(new AJPInputStream());

		return response;
	}

	private class AJPInputStream extends InputStream {

		private boolean closed = false;
		private byte[] buff = null;
		private int pos = 0;
		private int len = 0;

		public AJPInputStream() throws IOException {
			fill();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#available()
		 */
		@Override
		public int available() throws IOException {
			return len;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#close()
		 */
		@Override
		public void close() throws IOException {
			if (!closed) {
				byte[] b = new byte[1024];
				int got;
				while ((got = read(b)) > -1)
					;
				closed = true;
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#read()
		 */
		@Override
		public int read() throws IOException {
			if (this.len == 0 & closed)
				return -1;

			int ret = buff[pos];
			pos++;
			len--;
			if (len == 0)
				fill();
			return ret;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.io.InputStream#read(byte[], int, int)
		 */
		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (this.len == 0 && closed)
				return -1;

			int got = 0;
			do {
				int avail = Math.min(this.len, len);
				System.arraycopy(buff, pos, b, off, avail);
				pos += avail;
				this.len -= avail;
				got += avail;
				if (this.len == 0)
					fill();
			} while (got < len && this.len > 0);
			return got;
		}

		private void fill() throws IOException {
			readMessage(in, ajpResponse);
			int type = ajpResponse.getByte();
			if (type == AJPConstants.JK_AJP13_END_RESPONSE) {
				closed = true;
				state = State.IDLE;
			} else if (type == AJPConstants.JK_AJP13_SEND_BODY_CHUNK) {
				len = ajpResponse.peekInt();
				if (buff == null || buff.length < len)
					buff = new byte[len];
				int got = ajpResponse.getBytes(buff);
				if (got != len)
					throw new IllegalStateException(
							"buffer lengths did not match!");
			}
		}

	}

	private void translate(RequestHeader request, AJPMessage message)
			throws MessageFormatException {
		message.reset();
		message.appendByte(AJPConstants.JK_AJP13_FORWARD_REQUEST);
		int method = AJPConstants.getRequestMethodIndex(request.getMethod());
		if (method == 0)
			throw new RuntimeException("Unsupported request method: "
					+ request.getMethod());
		message.appendByte(method);
		message.appendString(request.getVersion());
		String resource = request.getResource();
		String query = null;
		int q = resource.indexOf('?');
		if (q > -1) {
			query = resource.substring(q + 1);
			resource = resource.substring(0, q);
		}
		message.appendString(resource); // resource
		message.appendString(getRemoteAddress()); // remote_addr
		message.appendString(getRemoteHost()); // remote_host
		message.appendString(request.getTarget().getHostName()); // server_name
		message.appendInt(request.getTarget().getPort()); // server_port
		message.appendBoolean(request.isSsl()); // is_ssl
		NamedValue[] headers = request.getHeaders();
		if (headers == null)
			headers = new NamedValue[0];
		message.appendInt(headers.length);
		for (int i = 0; i < headers.length; i++) {
			appendRequestHeader(message, headers[i]);
		}

		appendRequestAttribute(message, AJPConstants.SC_A_CONTEXT, context);
		appendRequestAttribute(message, AJPConstants.SC_A_SERVLET_PATH,
				servletPath);
		appendRequestAttribute(message, AJPConstants.SC_A_REMOTE_USER, remoteUser);
		appendRequestAttribute(message, AJPConstants.SC_A_AUTH_TYPE, authType);
		appendRequestAttribute(message, AJPConstants.SC_A_QUERY_STRING, query);
		appendRequestAttribute(message, AJPConstants.SC_A_JVM_ROUTE, route);
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_CERT, sslCert);
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_CIPHER, sslCipher);
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_SESSION, sslSession);
		appendRequestAttributes(message, AJPConstants.SC_A_REQ_ATTRIBUTE,
				requestAttributes);
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_KEY_SIZE, sslKeySize);
		appendRequestAttribute(message, AJPConstants.SC_A_SECRET, secret);
		appendRequestAttribute(message, AJPConstants.SC_A_STORED_METHOD,
				storedMethod);

		message.appendByte(AJPConstants.SC_A_ARE_DONE);
		message.end(AJPMessage.AJP_CLIENT);
	}

	private static void appendRequestHeader(AJPMessage message,
			NamedValue header) {
		int code = AJPConstants.getRequestHeaderIndex(header.getName());
		if (code > 0) {
			message.appendInt(code);
		} else {
			message.appendString(header.getName());
		}
		message.appendString(header.getValue());
	}

	private void appendRequestAttribute(AJPMessage message, byte attribute,
			String value) {
		if (value == null)
			return;
		message.appendByte(attribute);
		message.appendString(value);
	}

	private void appendRequestAttributes(AJPMessage message, byte attribute,
			Map<String, String> values) {
		if (values == null || values.size() == 0)
			return;
		Iterator<Entry<String, String>> it = values.entrySet().iterator();
		while (it.hasNext()) {
			Entry<String, String> entry = it.next();
			message.appendByte(AJPConstants.SC_A_REQ_ATTRIBUTE);
			message.appendString(entry.getKey());
			message.appendString(entry.getValue());
		}
	}

	private static void translate(AJPMessage message,
			MutableResponseHeader response) throws MessageFormatException {
		byte messageType = message.getByte();
		if (messageType != AJPConstants.JK_AJP13_SEND_HEADERS)
			throw new RuntimeException("Expected SEND_HEADERS, got "
					+ messageType);
		int status = message.getInt();
		response.setVersion("HTTP/1.1"); // must be, surely?
		response.setStatus(Integer.toString(status));
		String reason = message.getString();
		response.setReason(reason);
		int n = message.getInt();
		for (int i = 0; i < n; i++) {
			byte code = message.peekByte();
			String name;
			if (code == 0xA0) {
				int index = message.getInt();
				name = AJPConstants.getResponseHeader(index);
			} else {
				name = message.getString();
			}
			response.addHeader(name, message.getString());
		}

	}

	/**
	 * Read an AJP message.
	 * 
	 * @return true if the message has been read, false if the short read didn't
	 *         return anything
	 * @throws IOException
	 *             any other failure, including incomplete reads
	 */
	private static void readMessage(InputStream in, AJPMessage message)
			throws IOException {

		byte[] buf = message.getBuffer();

		read(in, buf, 0, message.getHeaderLength());

		message.processHeader();
		read(in, buf, message.getHeaderLength(), message.getLen());
	}

	/**
	 * Read at least the specified amount of bytes, and place them in the input
	 * buffer.
	 */
	private static void read(InputStream in, byte[] buf, int pos, int n)
			throws IOException {

		int read = 0;
		int res = 0;
		while (read < n) {
			res = in.read(buf, read + pos, n - read);
			if (res > 0) {
				read += res;
			} else {
				throw new IOException("Read failed, got " + read + " of " + n);
			}
		}
	}

	public String getRemoteAddress() {
		if (remoteAddress == null) {
			return sock.getLocalAddress().getHostAddress();
		}
		return remoteAddress;
	}

	public String getRemoteHost() {
		if (remoteHost == null)
			return sock.getLocalAddress().getHostName();
		return remoteHost;
	}

	public void setRequestAttributes(Map<String, String> attributes) {
		this.requestAttributes = attributes;
	}

	public Map<String, String> getRequestAttributes() {
		if (requestAttributes == null)
			requestAttributes = new HashMap<String, String>();
		return requestAttributes;
	}

	/**
	 * @return the context
	 */
	public String getContext() {
		return context;
	}

	/**
	 * @param context
	 *            the context to set
	 */
	public void setContext(String context) {
		this.context = context;
	}

	/**
	 * @return the servletPath
	 */
	public String getServletPath() {
		return servletPath;
	}

	/**
	 * @param servletPath
	 *            the servletPath to set
	 */
	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	/**
	 * @return the remoteUser
	 */
	public String getRemoteUser() {
		return remoteUser;
	}

	/**
	 * @param remoteUser
	 *            the remoteUser to set
	 */
	public void setRemoteUser(String remoteUser) {
		this.remoteUser = remoteUser;
	}

	/**
	 * @return the authType
	 */
	public String getAuthType() {
		return authType;
	}

	/**
	 * @param authType
	 *            the authType to set
	 */
	public void setAuthType(String authType) {
		this.authType = authType;
	}

	/**
	 * @return the route
	 */
	public String getRoute() {
		return route;
	}

	/**
	 * @param route
	 *            the route to set
	 */
	public void setRoute(String route) {
		this.route = route;
	}

	/**
	 * @return the sslCert
	 */
	public String getSslCert() {
		return sslCert;
	}

	/**
	 * @param sslCert
	 *            the sslCert to set
	 */
	public void setSslCert(String sslCert) {
		this.sslCert = sslCert;
	}

	public void setSslCert(X509Certificate cert)
			throws CertificateEncodingException, IOException {
		StringBuilder buff = new StringBuilder();
		buff.append(START_CERTIFICATE);
		buff.append(Base64
				.encodeBytes(cert.getEncoded(), Base64.DO_BREAK_LINES));
		buff.append(END_CERTIFICATE);
		setSslCert(buff.toString());
	}

	/**
	 * @return the sslCipher
	 */
	public String getSslCipher() {
		return sslCipher;
	}

	/**
	 * @param sslCipher
	 *            the sslCipher to set
	 */
	public void setSslCipher(String sslCipher) {
		this.sslCipher = sslCipher;
	}

	/**
	 * @return the sslSession
	 */
	public String getSslSession() {
		return sslSession;
	}

	/**
	 * @param sslSession
	 *            the sslSession to set
	 */
	public void setSslSession(String sslSession) {
		this.sslSession = sslSession;
	}

	/**
	 * @return the sslKeySize
	 */
	public String getSslKeySize() {
		return sslKeySize;
	}

	/**
	 * @param sslKeySize
	 *            the sslKeySize to set
	 */
	public void setSslKeySize(String sslKeySize) {
		this.sslKeySize = sslKeySize;
	}

	/**
	 * @return the secret
	 */
	public String getSecret() {
		return secret;
	}

	/**
	 * @param secret
	 *            the secret to set
	 */
	public void setSecret(String secret) {
		this.secret = secret;
	}

	/**
	 * @return the storedMethod
	 */
	public String getStoredMethod() {
		return storedMethod;
	}

	/**
	 * @param storedMethod
	 *            the storedMethod to set
	 */
	public void setStoredMethod(String storedMethod) {
		this.storedMethod = storedMethod;
	}

	/**
	 * @param remoteAddress
	 *            the remoteAddress to set
	 */
	public void setRemoteAddress(String remoteAddress) {
		this.remoteAddress = remoteAddress;
	}

	/**
	 * @param remoteHost
	 *            the remoteHost to set
	 */
	public void setRemoteHost(String remoteHost) {
		this.remoteHost = remoteHost;
	}
}
