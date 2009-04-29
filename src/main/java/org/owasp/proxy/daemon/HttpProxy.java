package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocketFactory;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.ChunkedInputStream;
import org.owasp.httpclient.io.EofNotifyingInputStream;
import org.owasp.httpclient.io.FixedLengthInputStream;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.URI;

public abstract class HttpProxy extends SSLProxy {

	private final static byte[] NO_CERTIFICATE_HEADER = AsciiString
			.getBytes("HTTP/1.0 503 Service unavailable"
					+ " - SSL server certificate not available\r\n\r\n");

	private final static byte[] NO_CERTIFICATE_MESSAGE = AsciiString
			.getBytes("There is no SSL server certificate available for use");

	private final static byte[] ERROR_HEADER = AsciiString
			.getBytes("HTTP/1.0 500 OWASP Proxy Error\r\n"
					+ "Content-Type: text/html\r\nConnection: close\r\n\r\n");

	private final static String ERROR_MESSAGE1 = "<html><head><title>OWASP Proxy Error</title></head>"
			+ "<body><h1>OWASP Proxy Error</h1>"
			+ "OWASP Proxy encountered an error fetching the following request : <br/><pre>";

	private final static String ERROR_MESSAGE2 = "</pre><br/>The error was: <br/><pre>";

	private final static String ERROR_MESSAGE3 = "</pre></body></html>";

	private final static Logger logger = Logger.getLogger(HttpProxy.class
			.toString());

	public HttpProxy(InetSocketAddress listen, InetSocketAddress target,
			SOCKS socks, SSL ssl) throws IOException {
		super(listen, target, socks, ssl);
		// logger.setLevel(Level.FINE);
	}

	/**
	 * Construct a response to the specified request. Note that this method must
	 * be thread-safe
	 * 
	 * @param source
	 *            TODO
	 * @param request
	 *            received from the client
	 * 
	 * @return the response to return to the client
	 * @throws IOException
	 *             if the response cannot be obtained, or if the request content
	 *             cannot be read
	 */
	protected abstract StreamingResponse handleRequest(InetAddress source,
			StreamingRequest request) throws IOException;

	protected abstract void close();

	protected StreamingResponse createErrorResponse(StreamingRequest request,
			Exception e) throws IOException {
		StringBuilder buff = new StringBuilder();
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(ERROR_HEADER);
		buff.append(ERROR_MESSAGE1);
		buff.append(AsciiString.create(request.getHeader()));
		buff.append(ERROR_MESSAGE2);
		StringWriter out = new StringWriter();
		e.printStackTrace(new PrintWriter(out));
		buff.append(out.getBuffer());
		buff.append(ERROR_MESSAGE3);
		response.setContent(new ByteArrayInputStream(AsciiString.getBytes(buff
				.toString())));
		return response;
	}

	private void doConnect(Socket socket, RequestHeader request)
			throws IOException, GeneralSecurityException,
			MessageFormatException {
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
		InetSocketAddress target = new InetSocketAddress(host, port);
		SSLSocketFactory socketFactory = getSSLSocketFactory(target);
		OutputStream out = socket.getOutputStream();
		if (socketFactory == null) {
			out.write(NO_CERTIFICATE_HEADER);
			out.write(NO_CERTIFICATE_MESSAGE);
			out.flush();
		} else {
			out.write("HTTP/1.0 200 Ok\r\n\r\n".getBytes());
			out.flush();
			// start over from the beginning to handle this
			// connection as an SSL connection
			socket = negotiateSsl(socket, socketFactory);
			handleConnection(socket, target, true);
		}
	}

	private StreamingRequest readRequest(InputStream in) throws IOException,
			MessageFormatException {
		logger.fine("Entering readRequest()");
		// read the whole header.
		ByteArrayOutputStream copy = new ByteArrayOutputStream();
		CopyInputStream cis = new CopyInputStream(in, copy);
		try {
			String line;
			do {
				line = cis.readLine();
			} while (line != null && !"".equals(line));
		} catch (IOException e) {
			byte[] headerBytes = copy.toByteArray();
			if (headerBytes == null || headerBytes.length == 0)
				return null;
			logger.fine("Read incomplete request header: \n"
					+ AsciiString.create(headerBytes));
			throw e;
		}

		byte[] headerBytes = copy.toByteArray();

		// empty request line, connection closed?
		if (headerBytes == null || headerBytes.length == 0)
			return null;

		StreamingRequest request = new StreamingRequest.Impl();
		request.setHeader(headerBytes);

		String transferCoding = request.getHeader("Transfer-Coding");
		String contentLength = request.getHeader("Content-Length");
		if (transferCoding != null
				&& transferCoding.trim().equalsIgnoreCase("chunked")) {
			in = new ChunkedInputStream(in, true); // don't unchunk
		} else if (contentLength != null) {
			try {
				in = new FixedLengthInputStream(in, Integer
						.parseInt(contentLength));
			} catch (NumberFormatException nfe) {
				IOException ioe = new IOException(
						"Invalid content-length header: " + contentLength);
				ioe.initCause(nfe);
				throw ioe;
			}
		} else {
			in = null;
		}

		request.setContent(in);
		return request;
	}

	private void extractTargetFromResource(RequestHeader request)
			throws MessageFormatException {
		String resource = request.getResource();
		try {
			URI uri = new URI(resource);
			request.setSsl("https".equals(uri.getScheme()));
			int port = uri.getPort() > 0 ? uri.getPort()
					: request.isSsl() ? 443 : 80;
			request.setTarget(new InetSocketAddress(uri.getHost(), port));
			request.setResource(uri.getResource());
		} catch (URISyntaxException use) {
			throw new MessageFormatException(
					"Couldn't parse resource as a URI", use);
		}
	}

	private void extractTargetFromHost(RequestHeader request)
			throws MessageFormatException {
		String host = request.getHeader("Host");
		int colon = host.indexOf(':');
		if (colon > -1) {
			try {
				String h = host.substring(0, colon);
				int port = Integer.parseInt(host.substring(colon + 1).trim());
				request.setTarget(new InetSocketAddress(h, port));
			} catch (NumberFormatException nfe) {
				throw new MessageFormatException(
						"Couldn't parse target port from Host: header", nfe);
			}
		} else {
			int port = request.isSsl() ? 443 : 80;
			request.setTarget(new InetSocketAddress(host, port));
		}
	}

	protected final void handleConnection(Socket socket,
			InetSocketAddress target, boolean ssl) {
		try {
			InetAddress source = socket.getInetAddress();

			InputStream in;
			OutputStream out;
			try {
				in = socket.getInputStream();
				out = socket.getOutputStream();
			} catch (IOException ioe) {
				// shouldn't happen
				ioe.printStackTrace();
				return;
			}

			boolean close;
			String version = null, connection = null;
			final StateHolder holder = new StateHolder();
			do {
				if (!holder.state.equals(State.READY))
					throw new IllegalStateException(
							"Trying to read a new request in state "
									+ holder.state);
				StreamingRequest request = null;
				try {
					request = readRequest(in);
					holder.state = State.REQUEST_HEADER;
				} catch (IOException ioe) {
					logger.info("Error reading request: " + ioe.getMessage());
					return;
				}
				if (request == null)
					return;

				if ("CONNECT".equals(request.getMethod())) {
					doConnect(socket, request);
					return;
				} else if (!request.getResource().startsWith("/")) {
					extractTargetFromResource(request);
				} else if (target != null) {
					request.setTarget(target);
					request.setSsl(ssl);
				} else if (request.getHeader("Host") != null) {
					extractTargetFromHost(request);
					request.setSsl(ssl);
				}

				InputStream requestContent = request.getContent();
				if (requestContent != null) {
					request.setContent(new EofNotifyingInputStream(
							requestContent) {
						@Override
						public void eof() {
							// all request content has been read
							holder.state = State.REQUEST_CONTENT;
						}
					});
				} else {
					// nonexistent content has been read :-)
					holder.state = State.REQUEST_CONTENT;
				}

				StreamingResponse response = null;
				try {
					response = handleRequest(source, request);
					holder.state = State.RESPONSE_HEADER;
				} catch (IOException ioe) {
					response = createErrorResponse(request, ioe);
				}

				try {
					out.write(response.getHeader());
				} catch (IOException ioe) { // client gone
					return;
				}
				InputStream content = response.getContent();
				int count = 0;
				try {
					byte[] buff = new byte[4096];
					int got;
					while ((got = content.read(buff)) > -1) {
						try {
							out.write(buff, 0, got);
							count += got;
						} catch (IOException ioe) { // client gone
							content.close();
							return;
						}
					}
					out.flush();
				} catch (IOException ioe) { // server closed
					logger.fine("Request was " + request);
					logger.fine("Incomplete response content: "
							+ ioe.getMessage());
					logger.fine("Read " + count + " bytes");
					return;
				}
				holder.state = State.READY;
				version = response.getVersion();
				connection = response.getHeader("Connection");

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
			} while (!close);
		} catch (GeneralSecurityException gse) {
			logger.severe(gse.getMessage());
		} catch (IOException ioe) {
			logger.info(ioe.getMessage());
		} catch (MessageFormatException mfe) {
			logger.info(mfe.getMessage());
			mfe.printStackTrace();
		} finally {
			if (!socket.isClosed()) {
				try {
					socket.close();
				} catch (IOException ignore) {
				}
			}
			close();
		}

	}

	private static class StateHolder {
		public State state = State.READY;
	}

	private enum State {
		READY, REQUEST_HEADER, REQUEST_CONTENT, RESPONSE_HEADER, RESPONSE_CONTENT
	}

}
