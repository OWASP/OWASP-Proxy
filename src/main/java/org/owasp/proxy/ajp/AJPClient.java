package org.owasp.proxy.ajp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.MutableResponseHeader;
import org.owasp.proxy.httpclient.NamedValue;
import org.owasp.proxy.httpclient.RequestHeader;
import org.owasp.proxy.httpclient.StreamingRequest;
import org.owasp.proxy.httpclient.StreamingResponse;
import org.owasp.proxy.io.BufferedInputStream;

public class AJPClient {

	private static final byte[] PING;

	private static final AJPMessage PONG = new AJPMessage(16);

	static {
		AJPMessage msg = new AJPMessage(16);
		msg.reset();
		msg.appendByte(AJPConstants.JK_AJP13_CPING_REQUEST);
		msg.end(AJPMessage.AJP_CLIENT);
		PING = new byte[msg.getLen()];
		System.arraycopy(msg.getBuffer(), 0, PING, 0, msg.getLen());
	}

	private enum State {
		DISCONNECTED, IDLE, ASSIGNED
	}

	private Socket sock;

	private InputStream in;

	private OutputStream out;

	private State state = State.DISCONNECTED;

	private int timeout = 10000;

	private AJPProperties properties = new AJPProperties();

	private AJPMessage ajpRequest = new AJPMessage(8192),
			ajpResponse = new AJPMessage(8192);

	private long requestSubmissionTime, responseHeaderTime;

	public AJPClient() {
	}

	public void connect(InetSocketAddress target) throws IOException {
		connect(target, Proxy.NO_PROXY);
	}

	public void connect(InetSocketAddress target, Proxy proxy)
			throws IOException {
		try {
			close();
		} catch (IOException ignored) {
		}
		validateTarget(proxy.address());
		sock = new Socket(proxy);
		sock.connect(target);
		sock.setSoTimeout(timeout);
		in = sock.getInputStream();
		out = sock.getOutputStream();
		state = State.IDLE;
	}

	public void setTimeout(int timeout) throws IOException {
		sock.setSoTimeout(timeout);
	}

	public void close() throws IOException {
		if (sock != null) {
			if (!sock.isClosed()) {
				sock.close();
			}
		}
	}

	protected void validateTarget(SocketAddress target) throws IOException {
	}

	public boolean isConnected() {
		if (sock == null)
			return false;
		try {
			sock.setSoTimeout(10);
			int got = sock.getInputStream().read();
			if (got == -1)
				return false;
			throw new RuntimeException("Unexpected data read from socket: "
					+ got);
		} catch (SocketTimeoutException ste) {
			return true;
		} catch (IOException ioe) {
			return false;
		}
	}

	public boolean isIdle() {
		return State.IDLE.equals(state);
	}

	public boolean ping() throws IOException {
		if (!isConnected())
			throw new IOException("Not connected to server");
		if (!isIdle())
			throw new IllegalStateException("Client is currently assigned");
		out.write(PING);
		out.flush();
		readMessage(in, PONG);
		return PONG.peekByte() == AJPConstants.JK_AJP13_CPONG_REPLY;
	}

	public StreamingResponse fetchResponse(StreamingRequest request)
			throws MessageFormatException, IOException {
		if (!isConnected())
			throw new IOException("Not connected to server");
		if (!isIdle())
			throw new IllegalStateException("Client is currently assigned");

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
		requestSubmissionTime = System.currentTimeMillis();

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
			requestSubmissionTime = System.currentTimeMillis();
			readMessage(in, ajpResponse);
			type = ajpResponse.peekByte();
		}

		StreamingResponse response = new StreamingResponse.Impl();
		if (type == AJPConstants.JK_AJP13_SEND_HEADERS) {
			responseHeaderTime = System.currentTimeMillis();
			translate(ajpResponse, response);
		} else
			throw new IllegalStateException(
					"Expected message of type SEND_HEADERS, got " + type);

		response.setContent(new AJPResponseInputStream(in));

		return response;
	}

	private class AJPResponseInputStream extends BufferedInputStream {

		public AJPResponseInputStream(InputStream in) throws IOException {
			super(in);
		}

		protected void fillBuffer() throws IOException {
			readMessage(in, ajpResponse);
			int type = ajpResponse.getByte();
			if (type == AJPConstants.JK_AJP13_END_RESPONSE) {
				state = State.IDLE;
				buff = null;
				start = 0;
				end = 0;
			} else if (type == AJPConstants.JK_AJP13_SEND_BODY_CHUNK) {
				int len = ajpResponse.peekInt();
				if (buff == null || buff.length < len)
					buff = new byte[len];
				int got = ajpResponse.getBytes(buff);
				if (got != len)
					throw new IllegalStateException(
							"buffer lengths did not match!");
				start = 0;
				end = len;
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

		appendRequestAttribute(message, AJPConstants.SC_A_CONTEXT, properties
				.getContext());
		appendRequestAttribute(message, AJPConstants.SC_A_SERVLET_PATH,
				properties.getServletPath());
		appendRequestAttribute(message, AJPConstants.SC_A_REMOTE_USER,
				properties.getRemoteUser());
		appendRequestAttribute(message, AJPConstants.SC_A_AUTH_TYPE, properties
				.getAuthType());
		appendRequestAttribute(message, AJPConstants.SC_A_QUERY_STRING, query);
		appendRequestAttribute(message, AJPConstants.SC_A_JVM_ROUTE, properties
				.getRoute());
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_CERT, properties
				.getSslCert());
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_CIPHER,
				properties.getSslCipher());
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_SESSION,
				properties.getSslSession());
		appendRequestAttributes(message, AJPConstants.SC_A_REQ_ATTRIBUTE,
				properties.getRequestAttributes());
		appendRequestAttribute(message, AJPConstants.SC_A_SSL_KEY_SIZE,
				properties.getSslKeySize());
		appendRequestAttribute(message, AJPConstants.SC_A_SECRET, properties
				.getSecret());
		appendRequestAttribute(message, AJPConstants.SC_A_STORED_METHOD,
				properties.getStoredMethod());

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

	private String getRemoteAddress() {
		String remoteAddress = properties.getRemoteAddress();
		if (remoteAddress != null)
			return remoteAddress;
		return sock.getLocalAddress().getHostAddress();
	}

	private String getRemoteHost() {
		String remoteHost = properties.getRemoteHost();
		if (remoteHost != null)
			return remoteHost;
		return sock.getLocalAddress().getHostName();
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
			if (code == (byte) 0xA0) {
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

		message.reset();

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

	/**
	 * @return the requestSubmissionTime
	 */
	public long getRequestSubmissionTime() {
		return requestSubmissionTime;
	}

	/**
	 * @return the responseHeaderStartTime
	 */
	public long getResponseHeaderTime() {
		return responseHeaderTime;
	}

}
