package org.owasp.httpclient;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.httpclient.io.ChunkedInputStream;
import org.owasp.httpclient.io.FixedLengthInputStream;
import org.owasp.httpclient.util.AsciiString;

public class Client {

	public static final ProxySelector NO_PROXY = new ProxySelector() {

		@Override
		public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
		}

		@Override
		public List<Proxy> select(URI uri) {
			return Arrays.asList(Proxy.NO_PROXY);
		}
	};

	private static final InputStream NO_CONTENT = new ByteArrayInputStream(
			new byte[0]);

	public enum State {
		DISCONNECTED, CONNECTED, REQUEST_HEADER_SENT, REQUEST_CONTENT_SENT, RESPONSE_HEADER_READ, RESPONSE_CONTINUE, RESPONSE_CONTENT_IN_PROGRESS, RESPONSE_CONTENT_READ
	}

	private SSLContextSelector contextSelector = new DefaultSSLContextSelector();

	private ProxySelector proxySelector = null;

	private AddressResolver resolver = null;

	private Socket socket = null;

	private InetSocketAddress target = null;

	private boolean direct = true;

	private State state = State.DISCONNECTED;

	private boolean expectResponseContent;

	private InputStream responseContent = null;

	public Client() {
	}

	public void setProxySelector(ProxySelector proxySelector) {
		this.proxySelector = proxySelector;
	}

	public ProxySelector getProxySelector() {
		if (proxySelector == null)
			return NO_PROXY;
		return proxySelector;
	}

	public void setSslContextSelector(SSLContextSelector contextSelector) {
		this.contextSelector = contextSelector;
	}

	public void setAddressResolver(AddressResolver resolver) {
		this.resolver = resolver;
	}

	public State getState() {
		return state;
	}

	protected boolean checkLoop(SocketAddress target) {
		return false;
	}

	private URI constructUri(boolean ssl, String host, int port)
			throws IOException {
		StringBuilder buff = new StringBuilder();
		buff.append(ssl ? "https" : "http").append("://").append(host).append(
				":").append(port);
		try {
			return new URI(buff.toString());
		} catch (URISyntaxException use) {
			IOException ioe = new IOException("Unable to construct a URI");
			ioe.initCause(use);
			throw ioe;
		}
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
						System.err
								.println("Unexpected data read from socket:\n\n"
										+ AsciiString.create(buff, 0, got));
						socket.close();
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

	private void proxyConnect(InetSocketAddress target) throws IOException {
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket
				.getOutputStream()));
		bw.write("CONNECT " + target.getHostName() + ":" + target.getPort()
				+ " HTTP/1.0\r\n\r\n");
		bw.flush();
		BufferedReader br = new BufferedReader(new InputStreamReader(socket
				.getInputStream()));
		String line = br.readLine();
		if (line == null)
			throw new IOException("Proxy closed connection without replying");
		int pos = "HTTP/1.x ".length();
		String status = line.substring(pos);
		if (!status.startsWith("200 "))
			throw new IOException("Proxy responded: " + status);
		do {
			line = br.readLine();
		} while (br != null && !"".equals(line));
	}

	public void connect(String host, int port, boolean ssl) throws IOException {
		if (state != State.DISCONNECTED)
			disconnect();
		if (host == null)
			throw new IllegalArgumentException(
					"Host is not set, don't know where to connect to!");

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

		this.target = target;

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
						proxyConnect(target);
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
				if (socket != null) {
					socket.close();
					socket = null;
				}
			}
			if (socket != null && socket.isConnected()) {
				// success
				state = State.CONNECTED;
				return;
			}
		}
		if (lastAttempt != null)
			throw lastAttempt;
		throw new IOException("Couldn't connect to server");
	}

	private void layerSsl(InetSocketAddress target) throws IOException {
		if (contextSelector == null)
			throw new IllegalStateException(
					"SSL Context Selector is null, SSL is not supported!");
		SSLContext sslContext = contextSelector.select(target);
		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsocket.setUseClientMode(true);
		sslsocket.setSoTimeout(10000);
		sslsocket.startHandshake();
		socket = sslsocket;
	}

	public void sendRequestHeader(byte[] header) throws IOException,
			MessageFormatException {
		if (state != State.CONNECTED)
			throw new IllegalStateException(
					"Illegal state. Can't send request headers when state is "
							+ state);
		OutputStream os = new BufferedOutputStream(socket.getOutputStream());

		int resourceStart = -1;
		String method = null;
		for (int i = 0; i < header.length; i++) {
			if (method == null && Character.isWhitespace(header[i])) {
				method = AsciiString.create(header, 0, i - 1);
			}
			if (method != null && !Character.isWhitespace(header[i])
					&& resourceStart == -1) {
				resourceStart = i;
				break;
			}
			if (header[i] == '\r' || header[i] == '\n')
				throw new MessageFormatException(
						"Encountered CR or LF when parsing the URI!");
		}
		expectResponseContent = !"HEAD".equals(method);
		if (!direct) {
			if (resourceStart > 0) {
				os.write(header, 0, resourceStart);
				os.write(("http://" + target.getHostName() + ":" + target
						.getPort()).getBytes());
				os.write(header, resourceStart, header.length - resourceStart);
			} else {
				throw new MessageFormatException("Couldn't parse the URI!");
			}
		} else {
			os.write(header);
		}
		os.flush();
		state = State.REQUEST_HEADER_SENT;
	}

	public void sendRequestContent(byte[] content) throws IOException {
		if (state != State.REQUEST_HEADER_SENT)
			throw new IllegalStateException(
					"Ilegal state. Can't send request content when state is "
							+ state);
		OutputStream os = socket.getOutputStream();
		os.write(content);
		os.flush();
		state = State.REQUEST_CONTENT_SENT;
	}

	public void sendRequestContent(InputStream content) throws IOException {
		if (state != State.REQUEST_HEADER_SENT)
			throw new IllegalStateException(
					"Ilegal state. Can't send request content when state is "
							+ state);
		OutputStream os = socket.getOutputStream();
		byte[] buff = new byte[1024];
		int got;
		while ((got = content.read(buff)) > 0)
			os.write(buff, 0, got);
		os.flush();
		state = State.REQUEST_CONTENT_SENT;
	}

	public byte[] getResponseHeader() throws IOException,
			MessageFormatException {
		if (state != State.REQUEST_HEADER_SENT
				&& state != State.REQUEST_CONTENT_SENT
				&& state != State.RESPONSE_CONTINUE)
			throw new IllegalStateException(
					"Ilegal state. Can't read response header when state is "
							+ state);
		InputStream is = socket.getInputStream();
		HeaderByteArrayOutputStream header = new HeaderByteArrayOutputStream();
		int i = -1;
		while (!header.isEndOfHeader() && (i = is.read()) > -1)
			header.write(i);
		if (i == -1)
			throw new IOException("Unexpected end of stream reading header");
		ResponseHeader rh = new ResponseHeader();
		rh.setHeader(header.toByteArray());
		String status = rh.getStatus();
		if (status.equals("100")) {
			state = State.RESPONSE_CONTINUE;
		} else {
			state = State.RESPONSE_HEADER_READ;
			if ("204".equals(status) || "304".equals(status)
					|| !expectResponseContent) {
				responseContent = NO_CONTENT;
			} else {
				String transferCoding = rh.getHeader("Transfer-Coding");
				String contentLength = rh.getHeader("Content-Length");
				if (transferCoding != null
						&& transferCoding.trim().equalsIgnoreCase("chunked")) {
					is = new ChunkedInputStream(is, true);
				} else if (contentLength != null) {
					try {
						is = new FixedLengthInputStream(is, Integer
								.parseInt(contentLength));
					} catch (NumberFormatException nfe) {
						IOException ioe = new IOException(
								"Invalid content-length header: "
										+ contentLength);
						ioe.initCause(nfe);
						throw ioe;
					}
				}
				responseContent = is;
			}
		}
		return rh.getHeader();
	}

	public InputStream getResponseContent() throws IOException {
		if (state != State.RESPONSE_HEADER_READ)
			throw new IllegalStateException(
					"Illegal state. Can't read response body when state is "
							+ state);
		state = State.RESPONSE_CONTENT_IN_PROGRESS;
		return new EofNotifyingInputStream(responseContent);
	}

	public void disconnect() throws IOException {
		try {
			if (socket != null && !socket.isClosed())
				socket.close();
		} finally {
			socket = null;
			state = State.DISCONNECTED;
		}
	}

	private static class HeaderByteArrayOutputStream extends
			ByteArrayOutputStream {

		// we do it here because we have direct access to the buffer
		public boolean isEndOfHeader() {
			int i = count;
			return i > 4 && buf[i - 4] == '\r' && buf[i - 3] == '\n'
					&& buf[i - 2] == '\r' && buf[i - 1] == '\n';
		}

	}

	private class EofNotifyingInputStream extends FilterInputStream {

		public EofNotifyingInputStream(InputStream in) {
			super(in);
		}

		@Override
		public int read() throws IOException {
			int result = super.read();
			if (result == -1)
				state = State.RESPONSE_CONTENT_READ;
			return result;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			int result = super.read(b, off, len);
			if (result == -1)
				state = State.RESPONSE_CONTENT_READ;
			return result;
		}

	}
}
