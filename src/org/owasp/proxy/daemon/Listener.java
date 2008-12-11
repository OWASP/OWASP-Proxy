package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

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
class Listener implements Runnable {

	private String base;

	private ProxyMonitor monitor;

	private volatile ServerSocket socket = null;

	private final static Logger logger = Logger.getLogger(Listener.class
			.getName());

	public Listener(int port) throws IOException {
		this(null, port);
	}

	public Listener(InetAddress address, int port) throws IOException {
		this(address, port, null);
	}

	public Listener(InetAddress address, int port, String base)
			throws IOException {
		this.base = base;
		socket = new ServerSocket(port, 20, address);
		socket.setReuseAddress(true);
	}

	public void run() {
		try {
			do {
				ConnectionHandler ch = new ConnectionHandler(socket.accept(),
						base);
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
		return true;
	}

	public synchronized boolean isStopped() {
		return socket == null || socket.isClosed();
	}

	private SSLSocketFactory getSocketFactory(String host, int port) {
		return null;
	}

	public ProxyMonitor getMonitor() {
		return monitor;
	}

	public void setProxyMonitor(ProxyMonitor monitor) {
		this.monitor = monitor;
	}

	protected HttpClient createHttpClient() {
		return new HttpClient();
	}

	private class ConnectionHandler implements Runnable {

		private final static String NO_CERTIFICATE_HEADER = "HTTP/1.0 503 Service unavailable - SSL server certificate not available\r\n\r\n";

		private final static String NO_CERTIFICATE_MESSAGE = "There is no SSL server certificate available for use";

		private final static String ERROR_HEADER = "HTTP/1.0 500 OWASP Proxy Error\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";

		private final static String ERROR_MESSAGE1 = "<html><head><title>OWASP Proxy Error</title></head><body><h1>OWASP Proxy Error</h1>"
				+ "OWASP Proxy encountered an error fetching the following request : <br/><pre>";

		private final static String ERROR_MESSAGE2 = "</pre><br/>The error was: <br/><pre>";

		private final static String ERROR_MESSAGE3 = "</pre></body></html>";

		private Socket socket;

		private String base;

		private HttpClient httpClient = null;

		public ConnectionHandler(Socket accept, String base) {
			this.socket = accept;
			this.base = base;
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
			String url = request.getUrl();
			int colon = url.indexOf(':');
			if (colon == -1)
				throw new MessageFormatException("Malformed CONNECT line : '"
						+ url + "'");
			String host = url.substring(0, colon);
			if (host.length() == 0)
				throw new MessageFormatException("Malformed CONNECT line : '"
						+ url + "'");
			int port;
			try {
				port = Integer.parseInt(url.substring(colon + 1));
			} catch (NumberFormatException nfe) {
				throw new MessageFormatException("Malformed CONNECT line : '"
						+ url + "'");
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
				base = "https://" + url + "/";
				run();
			}
		}

		private void insertBase(Request request) throws MessageFormatException {
			String url = request.getUrl();
			if (!url.startsWith("/"))
				throw new MessageFormatException(
						"Cannot prepend base to url: '" + url + "'");
			url = base + url;
			request.setUrl(url);
		}

		public void run() {
			try {
				ByteArrayOutputStream copy = new ByteArrayOutputStream();
				CopyInputStream in;
				OutputStream out;
				try {
					in = new CopyInputStream(socket.getInputStream(), copy);
					out = socket.getOutputStream();
				} catch (IOException ioe) {
					// shouldn't happen
					ioe.printStackTrace();
					return;
				}

				boolean close;
				do {
					Request request = null;
					try {
						// read the whole header. Each line gets written into
						// the copy defined above
						try {
							while (!"".equals(in.readLine()))
								;

						} catch (IOException ioe) {
							byte[] headerBytes = copy.toByteArray();
							// connection closed while waiting for a new request
							if (headerBytes == null || headerBytes.length == 0)
								return;
							throw ioe;
						}

						byte[] headerBytes = copy.toByteArray();

						// empty request line, connection closed?
						if (headerBytes == null || headerBytes.length == 0)
							return;

						request = new Request();
						request.setMessage(headerBytes);
						headerBytes = null;

						// Get the request content (if any) from the stream,
						if (Request.flushContent(request, in))
							request.setMessage(copy.toByteArray());

						// clear the stream copy
						copy.reset();

						if (base != null)
							insertBase(request);

						Response response = requestReceived(request);
						if (response != null) {
							out.write(response.getMessage());
							return;
						}

						if (request.getMethod().equals("CONNECT")) {
							copy = null;
							in = null;
							doConnect(out, request);
							return;
						}
					} catch (IOException ioe) {
						errorReadingRequest(request, ioe);
						return;
					} catch (MessageFormatException mfe) {
						errorReadingRequest(request, mfe);
						return;
					}

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

		private Response errorReadingRequest(Request request, Exception e)
				throws MessageFormatException {
			if (monitor != null) {
				try {
					return monitor.errorReadingRequest(request, e);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
			}
			return null;
		}

		private Response requestReceived(Request request)
				throws MessageFormatException {
			if (monitor != null) {
				try {
					return monitor.requestReceived(request);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return null;
		}

		private Response errorFetchingResponseHeader(Request request,
				Exception e) throws MessageFormatException {
			if (monitor != null) {
				try {
					return monitor.errorFetchingResponseHeader(request, e);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
			}
			return null;
		}

		private Response errorFetchingResponseContent(
				Conversation conversation, Exception e)
				throws MessageFormatException {
			if (monitor != null) {
				try {
					return monitor
							.errorFetchingResponseContent(conversation, e);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
			}
			return null;
		}

		private boolean responseHeaderReceived(Conversation conversation)
				throws MessageFormatException {
			if (monitor != null) {
				try {
					return monitor.responseHeaderReceived(conversation);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return true;
		}

		private void responseContentReceived(Conversation conversation,
				boolean streamed) throws MessageFormatException {
			if (monitor != null) {
				try {
					monitor.responseContentReceived(conversation, streamed);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		private void errorWritingResponseToBrowser(Conversation conversation,
				Exception e) throws MessageFormatException {
			if (monitor != null) {
				try {
					monitor.errorWritingResponseToBrowser(conversation, e);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
			}
		}

		private void wroteResponseToBrowser(Conversation conversation)
				throws MessageFormatException {
			if (monitor != null) {
				try {
					monitor.wroteResponseToBrowser(conversation);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

	}

	public static void main(String[] args) throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] { 127, 0,
				0, 1 }), 9998);
		l.setProxyMonitor(new ProxyMonitor() {

			@Override
			public Response requestReceived(Request request)
					throws MessageFormatException {
				Response ret = super.requestReceived(request);
				try {
					System.out.write(request.getMessage());
				} catch (IOException ioe) {
				}
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
				return true;
			}

			@Override
			public void responseContentReceived(Conversation conversation,
					boolean streamed) throws MessageFormatException {
			}

			@Override
			public void wroteResponseToBrowser(Conversation conversation)
					throws MessageFormatException {
				int resp = conversation.getResponse().getMessage().length;
				long time = conversation.getResponseBodyTime();
				if (time == 0)
					time = conversation.getResponseHeaderTime();
				time = time - conversation.getRequestTime();

				System.out.println(conversation.getRequest().getStartLine()
						+ " : " + conversation.getResponse().getStatus()
						+ " - " + resp + " bytes in " + time + " ("
						+ (resp * 1000 / time) + " bps)");
			}

		});
		Thread t = new Thread(l);
		t.setDaemon(true);
		t.start();

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
