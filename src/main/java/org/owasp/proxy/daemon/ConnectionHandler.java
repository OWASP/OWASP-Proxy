package org.owasp.proxy.daemon;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PushbackInputStream;
import java.net.Socket;
import java.net.URISyntaxException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.util.MessageUtils;
import org.owasp.proxy.httpclient.DefaultHttpClientFactory;
import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.HttpClientFactory;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.io.SocketWrapper;
import org.owasp.proxy.model.URI;

public class ConnectionHandler implements Runnable {

	private final static String NO_CERTIFICATE_HEADER = "HTTP/1.0 503 Service unavailable"
			+ " - SSL server certificate not available\r\n\r\n";

	private final static String NO_CERTIFICATE_MESSAGE = "There is no SSL server certificate available for use";

	private final static String ERROR_HEADER = "HTTP/1.0 500 OWASP Proxy Error\r\n"
			+ "Content-Type: text/html\r\nConnection: close\r\n\r\n";

	private final static String ERROR_MESSAGE1 = "<html><head><title>OWASP Proxy Error</title></head>"
			+ "<body><h1>OWASP Proxy Error</h1>"
			+ "OWASP Proxy encountered an error fetching the following request : <br/><pre>";

	private final static String ERROR_MESSAGE2 = "</pre><br/>The error was: <br/><pre>";

	private final static String ERROR_MESSAGE3 = "</pre></body></html>";

	private final static Logger logger = Logger
			.getLogger(ConnectionHandler.class.toString());

	private Socket socket;

	private boolean targetSsl = false;

	private String targetHost = null;

	private int targetPort = -1;

	private HttpClient httpClient = null;

	private ProxyMonitor monitor;

	private CertificateProvider certProvider = null;

	private HttpClientFactory clientFactory;

	public ConnectionHandler(Socket accept) {
		this.socket = accept;
	}

	public void setTarget(boolean ssl, String host, int port) {
		this.targetSsl = ssl;
		this.targetHost = host;
		this.targetPort = port;
	}

	public void setProxyMonitor(ProxyMonitor monitor) {
		this.monitor = monitor;
	}

	public void setCertificateProvider(CertificateProvider certProvider) {
		this.certProvider = certProvider;
	}

	public void setHttpClientFactory(HttpClientFactory clientFactory) {
		this.clientFactory = clientFactory;
	}

	private Socket negotiateSSL(SSLSocketFactory factory, Socket socket)
			throws IOException {
		SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsock.setUseClientMode(false);
		return sslsock;
	}

	private void writeErrorResponse(OutputStream out, Request request,
			Exception e) throws IOException {
		out.write(ERROR_HEADER.getBytes());
		out.write(ERROR_MESSAGE1.getBytes());
		out.write(request.getHeader());
		if (request.getContent() != null)
			out.write(request.getContent());
		out.write(ERROR_MESSAGE2.getBytes());
		e.printStackTrace(new PrintStream(out));
		out.write(ERROR_MESSAGE3.getBytes());
	}

	private SSLSocketFactory getSocketFactory(String host, int port)
			throws IOException {
		if (certProvider != null)
			return certProvider.getSocketFactory(host, port);
		return null;
	}

	private void doConnect(OutputStream out, Request request)
			throws IOException, MessageFormatException {
		String resource = request.getResource();
		int colon = resource.indexOf(':');
		if (colon == -1)
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'");
		String host = resource.substring(0, colon);
		if (host.length() == 0)
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'");
		int port;
		try {
			port = Integer.parseInt(resource.substring(colon + 1));
		} catch (NumberFormatException nfe) {
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'");
		}
		SSLSocketFactory socketFactory = getSocketFactory(host, port);
		if (socketFactory == null) {
			out.write(NO_CERTIFICATE_HEADER.getBytes());
			out.write(NO_CERTIFICATE_MESSAGE.getBytes());
			out.flush();
		} else {
			out.write("HTTP/1.0 200 Ok\r\n\r\n".getBytes());
			out.flush();
			out = null;
			// start over from the beginning to handle this
			// connection as an SSL connection
			socket = negotiateSSL(socketFactory, socket);
			targetSsl = true;
			targetHost = host;
			targetPort = port;
			run();
		}
	}

	private void readRequest(Request request, CopyInputStream in,
			ByteArrayOutputStream copy, OutputStream out) throws IOException,
			MessageFormatException {
		// read the whole header.
		try {
			while (!"".equals(in.readLine()))
				;
		} catch (IOException e) {
			byte[] headerBytes = copy.toByteArray();
			if (headerBytes == null || headerBytes.length == 0)
				return;
			request.setHeader(headerBytes);
			throw e;
		}

		byte[] headerBytes = copy.toByteArray();

		// empty request line, connection closed?
		if (headerBytes == null || headerBytes.length == 0)
			return;

		request.setHeader(headerBytes);
		headerBytes = null;

		// Get the request content (if any) from the stream,
		copy.reset();
		if (MessageUtils.expectContent(request)
				&& MessageUtils.flushContent(request, in))
			request.setContent(copy.toByteArray());

		// clear the stream copy
		copy.reset();
	}

	private boolean isSSL(byte[] sniff, int len) {
		for (int i = 0; i < len; i++)
			if (sniff[i] == 0x03)
				return true;
		return false;
	}

	private void extractTargetFromResource(Request request)
			throws MessageFormatException {
		String resource = request.getResource();
		try {
			URI uri = new URI(resource);
			request.setSsl("https".equals(uri.getScheme()));
			request.setHost(uri.getHost());
			request.setPort(uri.getPort());
			request.setResource(uri.getResource());
		} catch (URISyntaxException use) {
			throw new MessageFormatException(
					"Couldn't parse resource as a URI", use);
		}
	}

	private void extractTargetFromHost(Request request)
			throws MessageFormatException {
		String host = request.getHeader("Host");
		request.setSsl(socket instanceof SSLSocket);
		int colon = host.indexOf(':');
		if (colon > -1) {
			try {
				request.setHost(host.substring(0, colon));
				int port = Integer.parseInt(host.substring(colon + 1).trim());
				request.setPort(port);
			} catch (NumberFormatException nfe) {
				throw new MessageFormatException(
						"Couldn't parse target port from Host: header", nfe);
			}
		} else {
			request.setHost(host);
			request.setPort(request.isSsl() ? 443 : 80);
		}
	}

	public void run() {
		if (clientFactory == null)
			clientFactory = new DefaultHttpClientFactory();
		try {
			InputStream sockIn;
			OutputStream out;
			try {
				sockIn = socket.getInputStream();
				out = socket.getOutputStream();
			} catch (IOException ioe) {
				// shouldn't happen
				ioe.printStackTrace();
				return;
			}

			if (!targetSsl) {
				// check if it is an SSL Connection
				try {
					byte[] sslsniff = new byte[4];
					PushbackInputStream pbis = new PushbackInputStream(socket
							.getInputStream(), sslsniff.length);
					int got = pbis.read(sslsniff);
					pbis.unread(sslsniff, 0, got);
					if (isSSL(sslsniff, got)) {
						SSLSocketFactory factory = getSocketFactory(targetHost,
								targetPort);
						if (factory == null)
							return;
						SocketWrapper wrapper = new SocketWrapper(socket, pbis,
								out);
						socket = negotiateSSL(factory, wrapper);
						targetSsl = true;
						run();
						return;
					} else {
						sockIn = pbis;
					}
				} catch (IOException ioe) {
					// unexpected end of stream (or socket timeout)
					return;
				}
			}
			boolean close;
			String version = null, connection = null;
			do {
				ByteArrayOutputStream copy = new ByteArrayOutputStream();
				CopyInputStream in = new CopyInputStream(sockIn, copy);
				Request request = new Request.Impl();
				try {
					readRequest(request, in, copy, out);
					Response response = requestReceived(request);
					if (response != null) {
						out.write(response.getHeader());
						if (response.getContent() != null)
							out.write(response.getContent());
						out.flush();
						return;
						// FIXME no support for connection keep alive when
						// using custom responses??
					}
				} catch (Exception e) {
					Response response = errorReadingRequest(request, e);
					if (response == null) {
						writeErrorResponse(out, request, e);
					} else {
						out.write(response.getHeader());
						if (response.getContent() != null)
							out.write(response.getContent());
					}
					out.flush();
					return;
				}
				// request header may be null if a response has already been
				// sent to the browser
				// or if there was no Request to be read on the socket
				// (closed or timed out)
				if (request.getHeader() == null)
					return;

				// handle SSL requests, or find out where to connect to
				if ("CONNECT".equals(request.getMethod())) {
					doConnect(out, request);
					return;
				} else if (!request.getResource().startsWith("/")) {
					extractTargetFromResource(request);
				} else if (targetHost != null) {
					request.setHost(targetHost);
					request.setPort(targetPort);
					request.setSsl(targetSsl);
				} else if (request.getHeader("Host") != null) {
					extractTargetFromHost(request);
				}

				try {
					if (httpClient == null)
						httpClient = clientFactory.createHttpClient();
					httpClient.connect(request.getHost(), request.getPort(),
							request.isSsl());

					httpClient.sendRequestHeader(request.getHeader());
					httpClient.sendRequestContent(request.getContent());

					requestSent(request);

					byte[] responseHeader = httpClient.getResponseHeader();
					ResponseHeader header = new ResponseHeader.Impl();
					header.setHeader(responseHeader);

					version = header.getVersion();
					connection = header.getHeader("Connection");
					// String orig = httpClient.getConnection();
					// StringBuilder connection = new StringBuilder();
					// connection.append("[");
					// connection.append(socket.getRemoteSocketAddress());
					// connection.append("->");
					// connection.append(socket.getLocalSocketAddress());
					// connection.append("]-[").append(orig).append("]");
					InputStream content = httpClient.getResponseContent();
					responseReceived(request, header, content, out);
					out.flush();
				} catch (Exception e) {
					Response response = errorReadingResponse(request, null, e);
					if (response == null) {
						writeErrorResponse(out, request, e);
					} else {
						out.write(response.getHeader());
						if (response.getContent() != null)
							out.write(response.getContent());
					}
					out.flush();
					return;
				}
				if ("HTTP/1.1".equals(version)) {
					close = false;
				} else {
					close = true;
				}
				if ("close".equals(connection)) {
					close = true;
				} else if ("Keep-Alive".equalsIgnoreCase(connection)) {
					close = false;
				}
				copy = null;
			} while (!close);
		} catch (IOException ioe) {
			logger.info(ioe.getMessage());
		} catch (MessageFormatException mfe) {
			logger.severe(mfe.getMessage());
			mfe.printStackTrace();
		} finally {
			if (!socket.isClosed())
				try {
					socket.close();
				} catch (IOException ignore) {
				}
			if (httpClient != null) {
				try {
					httpClient.disconnect();
				} catch (IOException ignore) {
				}
			}
		}

	}

	private Response errorReadingRequest(Request request, Exception e) {
		if (monitor != null)
			try {
				return monitor.errorReadingRequest(request, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		return null;
	}

	private Response requestReceived(Request request) {
		if (monitor != null)
			try {
				return monitor.requestReceived(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
		return null;
	}

	private void requestSent(Request request) {
		if (monitor != null)
			try {
				monitor.requestSent(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
	}

	private Response errorReadingResponse(Request request,
			ResponseHeader header, Exception e) {
		if (monitor != null)
			try {
				return monitor.errorReadingResponse(request, header, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		return null;
	}

	private void responseReceived(Request request, ResponseHeader header,
			InputStream content, OutputStream client) {
		if (monitor != null)
			try {
				monitor.responseReceived(request, header, content, client);
			} catch (Exception e) {
				e.printStackTrace();
			}
	}

}
