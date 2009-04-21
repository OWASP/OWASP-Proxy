package org.owasp.proxy.daemon;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;
import org.owasp.proxy.httpclient.DefaultHttpClientFactory;
import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.HttpClientFactory;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.URI;

public class ConnectionHandler implements Runnable {

	private final static byte[] NO_CERTIFICATE_HEADER = AsciiString
			.getBytes("HTTP/1.0 503 Service unavailable"
					+ " - SSL server certificate not available\r\n\r\n");

	private final static byte[] NO_CERTIFICATE_MESSAGE = AsciiString
			.getBytes("There is no SSL server certificate available for use");

	private final static byte[] ERROR_HEADER = AsciiString
			.getBytes("HTTP/1.0 500 OWASP Proxy Error\r\n"
					+ "Content-Type: text/html\r\nConnection: close\r\n\r\n");

	private final static byte[] ERROR_MESSAGE1 = AsciiString
			.getBytes("<html><head><title>OWASP Proxy Error</title></head>"
					+ "<body><h1>OWASP Proxy Error</h1>"
					+ "OWASP Proxy encountered an error fetching the following request : <br/><pre>");

	private final static byte[] ERROR_MESSAGE2 = AsciiString
			.getBytes("</pre><br/>The error was: <br/><pre>");

	private final static byte[] ERROR_MESSAGE3 = AsciiString
			.getBytes("</pre></body></html>");

	private final static Logger logger = Logger
			.getLogger(ConnectionHandler.class.toString());

	private Socket socket;

	private Configuration config;

	private HttpClient httpClient = null;

	public ConnectionHandler(Socket accept, Configuration config) {
		this.socket = accept;
		this.config = config;
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
		out.write(ERROR_HEADER);
		out.write(ERROR_MESSAGE1);
		out.write(request.getHeader());
		if (request.getContent() != null)
			out.write(request.getContent());
		out.write(ERROR_MESSAGE2);
		e.printStackTrace(new PrintStream(out));
		out.write(ERROR_MESSAGE3);
	}

	private SSLSocketFactory getSocketFactory(InetSocketAddress target)
			throws IOException {
		try {
			CertificateProvider certProvider = config.getCertificateProvider();
			if (certProvider != null)
				return certProvider.getSocketFactory(target.getHostName(),
						target.getPort());
		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		}
		return null;
	}

	private void doConnect(OutputStream out, Request request)
			throws IOException, MessageFormatException {
		String resource = request.getResource();
		int colon = resource.indexOf(':');
		if (colon == -1)
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'", request.getHeader());
		String host = resource.substring(0, colon);
		if (host.length() == 0)
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'", request.getHeader());
		int port;
		try {
			port = Integer.parseInt(resource.substring(colon + 1));
		} catch (NumberFormatException nfe) {
			throw new MessageFormatException("Malformed CONNECT line : '"
					+ resource + "'", request.getHeader());
		}
		InetSocketAddress target = InetSocketAddress.createUnresolved(host,
				port);
		SSLSocketFactory socketFactory = getSocketFactory(target);
		if (socketFactory == null) {
			out.write(NO_CERTIFICATE_HEADER);
			out.write(NO_CERTIFICATE_MESSAGE);
			out.flush();
		} else {
			out.write("HTTP/1.0 200 Ok\r\n\r\n".getBytes());
			out.flush();
			out = null;
			// start over from the beginning to handle this
			// connection as an SSL connection
			socket = negotiateSSL(socketFactory, socket);
			config.setSsl(true);
			config.setTarget(target);
			run();
		}
	}

	private void readRequest(Request request, CopyInputStream in,
			ByteArrayOutputStream copy, OutputStream out) throws IOException,
			MessageFormatException {
		logger.info("Entering readRequest()");
		// read the whole header.
		try {
			String line;
			do {
				line = in.readLine();
			} while (line != null && !"".equals(line));
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
		connectionFromClient(socket);

		HttpClientFactory clientFactory = config.getHttpClientFactory();
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
				} else if (config.getTarget() != null) {
					InetSocketAddress target = config.getTarget();
					request.setHost(target.getHostName());
					request.setPort(target.getPort());
					request.setSsl(config.isSsl());
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
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null)
			try {
				return monitor.errorReadingRequest(request, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		return null;
	}

	private void connectionFromClient(Socket socket) {
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null)
			try {
				monitor.connectionFromClient(socket);
			} catch (Exception e) {
				e.printStackTrace();
			}
	}

	private Response requestReceived(Request request) {
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null)
			try {
				return monitor.requestReceived(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
		return null;
	}

	private void requestSent(Request request) {
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null)
			try {
				monitor.requestSent(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
	}

	private Response errorReadingResponse(Request request,
			ResponseHeader header, Exception e) {
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null)
			try {
				return monitor.errorReadingResponse(request, header, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		return null;
	}

	private void responseReceived(Request request, ResponseHeader header,
			InputStream content, OutputStream client) throws IOException {
		ProxyMonitor monitor = config.getProxyMonitor();
		if (monitor != null) {
			try {
				monitor.responseReceived(request, header, content, client);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			client.write(header.getHeader());
			byte[] buff = new byte[1024];
			int got;
			while ((got = content.read(buff)) > -1)
				client.write(buff, 0, got);
		}
	}

	public static class Configuration {

		private InetSocketAddress target = null;

		private boolean ssl = false;

		private ProxyMonitor proxyMonitor = null;

		private CertificateProvider certificateProvider = null;

		private HttpClientFactory httpClientFactory = null;

		/**
		 * @return the target
		 */
		public InetSocketAddress getTarget() {
			return target;
		}

		/**
		 * @param target
		 *            the target to set
		 */
		public void setTarget(InetSocketAddress target) {
			this.target = target;
		}

		/**
		 * @return the proxyMonitor
		 */
		public ProxyMonitor getProxyMonitor() {
			return proxyMonitor;
		}

		/**
		 * @param proxyMonitor
		 *            the proxyMonitor to set
		 */
		public void setProxyMonitor(ProxyMonitor proxyMonitor) {
			this.proxyMonitor = proxyMonitor;
		}

		/**
		 * @return the ssl
		 */
		public boolean isSsl() {
			return ssl;
		}

		/**
		 * @param ssl
		 *            the ssl to set
		 */
		public void setSsl(boolean ssl) {
			this.ssl = ssl;
		}

		/**
		 * @return the certificateProvider
		 */
		public CertificateProvider getCertificateProvider() {
			return certificateProvider;
		}

		/**
		 * @param certificateProvider
		 *            the certificateProvider to set
		 */
		public void setCertificateProvider(
				CertificateProvider certificateProvider) {
			this.certificateProvider = certificateProvider;
		}

		/**
		 * @return the httpClientFactory
		 */
		public HttpClientFactory getHttpClientFactory() {
			return httpClientFactory;
		}

		/**
		 * @param httpClientFactory
		 *            the httpClientFactory to set
		 */
		public void setHttpClientFactory(HttpClientFactory httpClientFactory) {
			this.httpClientFactory = httpClientFactory;
		}

	}
}
