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
package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.owasp.proxy.model.URI;

/**
 * This class implements an intercepting HTTP proxy, which can be customized to
 * modify and/or log the conversations passing through it in various ways. It
 * also supports streaming large responses directly to the browser, although
 * this behaviour can be controlled on a per-request basis.
 * 
 * The most basic proxy (that has no customized behaviour) should look like:
 * 
 * <code>
 * 	int port = . . .;
 * 	Listener listener = new Listener(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), port); 
 * 	Thread t = new Thread(listener);
 * 	t.setDaemon(true);
 * 	t.start();
 * 	
 * 	<wait for signal to stop>
 * 	
 * 	if (!listener.stop()) {
 * 		// error stopping listener 
 * 	}
 * </code>
 * 
 * Observing and influencing the proxy is accomplished through the ProxyMonitor.
 * 
 * @see Listener#setProxyMonitor(ProxyMonitor)
 * @see ProxyMonitor
 * 
 * @author Rogan Dawes
 * 
 */
public class Listener {

	private boolean ssl = false;
	
	private String host;

	private int port;

	private volatile ServerSocket socket = null;

	private final static Logger logger = Logger.getLogger(Listener.class
			.getName());

	public Listener(int listenPort) throws IOException {
		this(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), listenPort);
	}

	public Listener(InetAddress address, int listenPort) throws IOException {
		socket = new ServerSocket(listenPort, 20, address);
		socket.setReuseAddress(true);
	}

	public void setTarget(boolean ssl, String host, int port) {
		this.ssl = ssl;
		this.host = host;
		this.port = port;
	}

	private Runner runner = null;
	
	private class Runner implements Runnable {
		public void run() {
			try {
				do {
					ConnectionHandler ch = new ConnectionHandler(socket.accept());
					Thread thread = new Thread(ch);
					thread.setDaemon(true);
					thread.start();
				} while (!socket.isClosed());
			} catch (IOException ioe) {
				if (!isStopped()) {
					ioe.printStackTrace();
					logger.warning("Exception listening for connections: "
							+ ioe.getMessage());
				}
			}
			try {
				if (socket != null && !socket.isClosed())
					socket.close();
			} catch (IOException ioe) {
				logger.warning("Exception closing socket: " + ioe.getMessage());
			}
			synchronized (this) {
				notifyAll();
			}
		}
	}
	
	public synchronized void start() {
		if (runner != null)
			throw new IllegalStateException("Already running in another thread!");
		runner = new Runner();
		Thread thread = new Thread(runner);
		thread.setDaemon(true);
		thread.start();
	}
	
	public synchronized boolean stop() {
		if (!isStopped()) {
			try {
				socket.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			while (!isStopped()) {
				int loop = 0;
				try {
					wait(1000);
				} catch (InterruptedException ie) {
					loop++;
					if (loop > 10)
						return false;
				}
			}
		}
		runner = null;
		return true;
	}

	public synchronized boolean isStopped() {
		return socket == null || socket.isClosed();
	}

	private SSLSocketFactory sslSocketFactory = null;

	/**
	 * Override this method to control SSL support. The default implementation
	 * uses the same certificate for all hosts.
	 * 
	 * @param host
	 *            the host that the client wishes to CONNECT to
	 * @param port
	 *            the port that the client wishes to CONNECT to
	 * @return an SSLSocketFactory generated from the relevant server key
	 *         material
	 */
	protected SSLSocketFactory getSocketFactory(String host, int port) {
		if (sslSocketFactory == null) {
			try {
				String pn = getClass().getPackage().getName().replace('.', '/');
				KeyStore ks = KeyStore.getInstance("PKCS12");
				InputStream is = getClass().getClassLoader()
						.getResourceAsStream(pn + "/server.p12");
				if (is != null) {
					char[] ksp = "password".toCharArray();
					ks.load(is, ksp);
					KeyManagerFactory kmf = KeyManagerFactory
							.getInstance("SunX509");
					char[] kp = "password".toCharArray();
					kmf.init(ks, kp);
					SSLContext sslcontext = SSLContext.getInstance("SSLv3");
					sslcontext.init(kmf.getKeyManagers(), null, null);
					sslSocketFactory = sslcontext.getSocketFactory();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return sslSocketFactory;
	}

	protected HttpClient createHttpClient() {
		return new HttpClient();
	}

	/**
	 * Called when a request is received by the proxy. Changes can be made to
	 * the Request object to alter what may be sent to the server.
	 * 
	 * @param request
	 *            the Request received from the client
	 * @return a custom Response to be sent directly back to the client without
	 *         making any request to a server, or null to forward the Request
	 * @throws MessageFormatException
	 *             if the request cannot be parsed
	 */
	protected Response requestReceived(Request request)
			throws MessageFormatException {
		// String connection = request.getHeader("Connection");
		// String version = request.getVersion();
		// if ("HTTP/1.1".equals(version) && connection != null) {
		// String[] headers = connection.split(" *, *");
		// for (int i=0; i<headers.length; i++) {
		// String value = request.deleteHeader(headers[i]);
		// System.out.println("Deleting header " + headers[i] + ", was " +
		// value);
		// }
		// }
		// request.deleteHeader("Proxy-Connection");
		return null;
	}

	/**
	 * Called when an error is encountered while reading the request from the
	 * client.
	 * 
	 * @param request
	 * @param e
	 * @return a customized Response to be sent to the browser, or null to send
	 *         the default error message
	 * @throws MessageFormatException
	 *             if the request couldn't be parsed
	 */
	protected Response errorReadingRequest(Request request, Exception e)
			throws MessageFormatException {
		return null;
	}

	/**
	 * Called when the Response headers have been read from the server. The
	 * response content (if any) will not yet have been read. Analysis can be
	 * performed based on the headers to determine whether to intercept the
	 * complete response at a later stage. If you wish to intercept the complete
	 * response message at a later stage, return false from this method to
	 * disable streaming of the response content, otherwise the response would
	 * already have been written to the browser when responseContentReceived is
	 * called.
	 * 
	 * Note: If you modify the response headers in this method, be very careful
	 * not to affect the retrieval of the response content. For example,
	 * deleting a "Transfer-Encoding: chunked" header would be a bad idea!
	 * 
	 * @param conversation
	 * @return true to stream the response to the client as it is being read
	 *         from the server, or false to delay writing the response to the
	 *         client until after responseContentReceived is called
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	protected boolean responseHeaderReceived(Conversation conversation)
			throws MessageFormatException {
		return true;
	}

	/**
	 * Called after the Response content has been received from the server. If
	 * streamed is false, the response can be modified here, and the modified
	 * version will be written to the client.
	 * 
	 * @param conversation
	 * @param streamed
	 *            true if the response has already been written to the client
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	protected void responseContentReceived(Conversation conversation,
			boolean streamed) throws MessageFormatException {
	}

	/**
	 * Called in the event of an error occurring while reading the response
	 * header from the client
	 * 
	 * @param request
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	protected Response errorFetchingResponseHeader(Request request, Exception e)
			throws MessageFormatException {
		return null;
	}

	/**
	 * Called in the event of an error occurring while reading the response
	 * content from the client
	 * 
	 * @param conversation
	 * @param e
	 * @return a custom Response to be sent to the client, or null to use the
	 *         default
	 * @throws MessageFormatException
	 *             if either the request or response couldn't be parsed
	 */
	protected Response errorFetchingResponseContent(Conversation conversation,
			Exception e) throws MessageFormatException {
		return null;
	}

	protected void wroteResponseToBrowser(Conversation conversation)
			throws MessageFormatException {
	}

	protected void errorWritingResponseToBrowser(Conversation conversation,
			Exception e) throws MessageFormatException {
	}

	protected class ConnectionHandler implements Runnable {

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

		private Socket socket;

		private boolean targetSsl = false;
		
		private String targetHost = null;

		private int targetPort = -1;

		private HttpClient httpClient = null;

		public ConnectionHandler(Socket accept) {
			this.socket = accept;
			targetSsl = Listener.this.ssl;
			targetHost = Listener.this.host;
			targetPort = Listener.this.port;
			try {
				socket.setSoTimeout(0);
			} catch (SocketException se) {
				se.printStackTrace();
			}
		}

		private Socket negotiateSSL(SSLSocketFactory factory, Socket socket)
				throws IOException {
			SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
					.getInetAddress().getHostName(), socket.getPort(), true);
			sslsock.setUseClientMode(false);
			return sslsock;
		}

		private void writeErrorResponse(PrintStream out, Request request,
				Exception e) {
			try {
				out.write(ERROR_HEADER.getBytes());
				out.write(ERROR_MESSAGE1.getBytes());
				out.write(request.getMessage());
				out.write(ERROR_MESSAGE2.getBytes());
				e.printStackTrace(out);
				out.write(ERROR_MESSAGE3.getBytes());
			} catch (IOException ioe) {
				// just eat it
			}
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

		private Request readRequest(CopyInputStream in,
				ByteArrayOutputStream copy, OutputStream out) {
			Request request = null;
			Response response = null;
			try {
				// read the whole header.
				// The exact data read can be obtained from the
				// BytearrayInputStream defined above
				try {
					while (!"".equals(in.readLine()))
						;

				} catch (IOException ioe) {
					byte[] headerBytes = copy.toByteArray();
					// connection closed while waiting for a new request
					if (headerBytes == null || headerBytes.length == 0)
						return null;
					throw ioe;
				}

				byte[] headerBytes = copy.toByteArray();

				// empty request line, connection closed?
				if (headerBytes == null || headerBytes.length == 0)
					return null;

				request = new Request();
				request.setMessage(headerBytes);
				headerBytes = null;

				// Get the request content (if any) from the stream,
				if (Request.flushContent(request, in))
					request.setMessage(copy.toByteArray());

				// clear the stream copy
				copy.reset();

				if (targetHost != null) {
					request.setSsl(targetSsl);
					request.setHost(targetHost);
					request.setPort(targetPort);
				} else if (!"CONNECT".equals(request.getMethod())) {
					String resource = request.getResource();
					int css = resource.indexOf("://");
					if (css > 3 && css < 6) {
						try {
							URI uri = new URI(resource);
							request.setSsl("https".equals(uri.getScheme()));
							request.setHost(uri.getHost());
							request.setPort(uri.getPort());
							request.setResource(uri.getResource());
						} catch (URISyntaxException use) {
							throw new MessageFormatException(
									"Couldn't parse resource as a UR", use);
						}
					} else {
						String host = request.getHeader("Host");
						if (host == null)
							throw new MessageFormatException(
									"Couldn't determine target scheme/host/port");
						request.setSsl(socket instanceof SSLSocket);
						int colon = host.indexOf(':');
						if (colon > -1) {
							try {
								request.setHost(host.substring(0, colon));
								int port = Integer.parseInt(host.substring(
										colon + 1).trim());
								request.setPort(port);
							} catch (NumberFormatException nfe) {
								throw new MessageFormatException(
										"Couldn't parse target port from Host: header",
										nfe);
							}
						} else {
							request.setHost(host);
							request.setPort("https".equals(ssl) ? 443 : 80);
						}
					}
				}

				response = requestReceived(request);

				if (response == null && request.getMethod().equals("CONNECT")) {
					doConnect(out, request);
					return null;
				}
			} catch (IOException ioe) {
				response = errorReadingRequest(request, ioe);
			} catch (MessageFormatException mfe) {
				response = errorReadingRequest(request, mfe);
			}
			if (response != null) {
				try {
					out.write(response.getMessage());
				} catch (IOException ioe) {
					// just eat it
				}
				return null;
			} else {
				return request;
			}
		}

		public void run() {
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
				do {
					ByteArrayOutputStream copy = new ByteArrayOutputStream();
					CopyInputStream in = new CopyInputStream(sockIn, copy);
					Request request = readRequest(in, copy, out);
					// request may be null if a response has already been sent
					// to the browser
					// or if there was no Request to be read on the socket
					// (closed)
					if (request == null)
						return;

					Conversation conversation = null;
					try {
						if (httpClient == null)
							httpClient = createHttpClient();
						conversation = httpClient.fetchResponseHeader(request);
					} catch (IOException ioe) {
						errorFetchingResponseHeader(request, ioe);
						writeErrorResponse(new PrintStream(out), request, ioe);
						return;
					} catch (MessageFormatException mfe) {
						errorFetchingResponseHeader(request, mfe);
						writeErrorResponse(new PrintStream(out), request, mfe);
						return;
					}
					boolean stream = responseHeaderReceived(conversation);
					if (stream) {
						try {
							// message only contains headers at this point
							out.write(conversation.getResponse().getMessage());
							httpClient.fetchResponseContent(out);
							responseContentReceived(conversation, stream);
							wroteResponseToBrowser(conversation);
						} catch (IOException ioe) {
							errorFetchingResponseContent(conversation, ioe);
							return;
						}
					} else {
						try {
							httpClient.fetchResponseContent(null);
							responseContentReceived(conversation, stream);
						} catch (IOException ioe) {
							errorFetchingResponseContent(conversation, ioe);
							return;
						}
						try {
							out.write(conversation.getResponse().getMessage());
							wroteResponseToBrowser(conversation);
						} catch (IOException ioe) {
							errorWritingResponseToBrowser(conversation, ioe);
							return;
						}
					}
					String version = conversation.getResponse().getVersion();
					if ("HTTP/1.1".equals(version)) {
						close = false;
					} else {
						close = true;
					}
					String connection = conversation.getResponse().getHeader(
							"Connection");
					if ("close".equals(connection)) {
						close = true;
					} else if ("Keep-Alive".equalsIgnoreCase(connection)) {
						close = false;
					}
					copy = null;
				} while (!close);
			} catch (MessageFormatException mfe) {
				logger.severe(mfe.getMessage());
				mfe.printStackTrace();
			} finally {
				try {
					if (!socket.isClosed())
						socket.close();
				} catch (IOException ioe) {
				}
				if (httpClient != null) {
					try {
						httpClient.close();
					} catch (IOException ioe) {
						// just eat the exception
					}
				}
			}

		}

		private Response errorReadingRequest(Request request, Exception e) {
			try {
				return Listener.this.errorReadingRequest(request, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
			return null;
		}

		private Response requestReceived(Request request) {
			try {
				return Listener.this.requestReceived(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return null;
		}

		private Response errorFetchingResponseHeader(Request request,
				Exception e) {
			try {
				return Listener.this.errorFetchingResponseHeader(request, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
			return null;
		}

		private Response errorFetchingResponseContent(
				Conversation conversation, Exception e) {
			try {
				return Listener.this.errorFetchingResponseContent(conversation,
						e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
			return null;
		}

		private boolean responseHeaderReceived(Conversation conversation) {
			try {
				return Listener.this.responseHeaderReceived(conversation);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return true;
		}

		private void responseContentReceived(Conversation conversation,
				boolean streamed) {
			try {
				Listener.this.responseContentReceived(conversation, streamed);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		private void errorWritingResponseToBrowser(Conversation conversation,
				Exception e) {
			try {
				Listener.this.errorWritingResponseToBrowser(conversation, e);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}

		private void wroteResponseToBrowser(Conversation conversation) {
			try {
				Listener.this.wroteResponseToBrowser(conversation);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	public static void main(String[] args) throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] { 127, 0,
				0, 1 }), 9998) {
			@Override
			public Response requestReceived(Request request)
					throws MessageFormatException {
				Response ret = super.requestReceived(request);
				// try {
				// System.out.write(request.getMessage());
				// } catch (IOException ioe) {
				// }
				return ret;
			}

			@Override
			public Response errorFetchingResponseHeader(Request request,
					Exception e) throws MessageFormatException {
				try {
					System.err.println("Error fetching response header: \n");
					System.err.write(request.getMessage());
					e.printStackTrace(new PrintStream(System.err));
				} catch (IOException ioe) {
				}
				return null;
			}

			@Override
			public Response errorFetchingResponseContent(
					Conversation conversation, Exception e)
					throws MessageFormatException {
				try {
					System.err.println("Error fetching response content: \n");
					System.err.write(conversation.getRequest().getMessage());
					System.err.println();
					System.err.write(conversation.getResponse().getMessage());
					System.err.println();
					e.printStackTrace(new PrintStream(System.err));
				} catch (IOException ioe) {
				}
				return null;
			}

			@Override
			public Response errorReadingRequest(Request request, Exception e)
					throws MessageFormatException {
				try {
					System.err.println("Error reading request: \n");
					if (request != null)
						System.err.write(request.getMessage());
					e.printStackTrace(new PrintStream(System.err));
				} catch (IOException ioe) {
				}
				return null;

			}

			public void errorWritingResponseToBrowser(
					Conversation conversation, Exception e)
					throws MessageFormatException {
				try {
					System.err
							.println("Error writing response to browser: \nRequest:\n");
					System.err.write(conversation.getRequest().getMessage());
					System.err.println("Response: \n");
					System.err.write(conversation.getResponse().getMessage());
					e.printStackTrace(new PrintStream(System.err));
				} catch (IOException ioe) {
				}
			}

			@Override
			public boolean responseHeaderReceived(Conversation conversation)
					throws MessageFormatException {
				System.err.println(conversation.getResponse().getHeader("Connection"));
				return true;
			}

			@Override
			public void responseContentReceived(Conversation conversation,
					boolean streamed) throws MessageFormatException {
				// try {
				// System.err.write(conversation.getResponse().getHeader());
				// } catch (IOException ioe) {
				// }
			}

			@Override
			public void wroteResponseToBrowser(Conversation conversation)
					throws MessageFormatException {
//				int resp = conversation.getResponse().getMessage().length;
//				long time = conversation.getResponseBodyTime();
//				if (time == 0)
//					time = conversation.getResponseHeaderTime();
//				time = time - conversation.getRequestTime();

//				long max = Runtime.getRuntime().maxMemory();
//				long free = max + Runtime.getRuntime().freeMemory()
//						- Runtime.getRuntime().totalMemory();
//				String label = "Used " + toMB(max - free) + " of " + toMB(max)
//						+ "MB";
//
//				System.out.println("Transferred " + resp + ". " + label);
				// System.out.println(conversation.getRequest().getStartLine()
				// + " : " + conversation.getResponse().getStatus()
				// + " - " + resp + " bytes in " + time + " ("
				// + (resp * 1000 / time) + " bps)");

			}

		};
		l.start();

		System.out.println("Listener started, press Enter to exit");

		new BufferedReader(new InputStreamReader(System.in)).readLine();

		System.out.println("Exiting!");
		long s = System.currentTimeMillis();
		if (!l.stop()) {
			System.err.println("Failed to exit after "
					+ (System.currentTimeMillis() - s));
		} else {
			System.out.println("Exited in " + (System.currentTimeMillis() - s));
		}
	}

}
