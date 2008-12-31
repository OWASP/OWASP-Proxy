package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.owasp.proxy.socks.ProxyMessage;
import org.owasp.proxy.socks.ServerAuthenticator;
import org.owasp.proxy.socks.ServerAuthenticatorNone;
import org.owasp.proxy.socks.Socks4Message;
import org.owasp.proxy.socks.Socks5Message;
import org.owasp.proxy.socks.SocksConstants;
import org.owasp.proxy.socks.SocksException;

/**
 * SOCKS4 and SOCKS5 proxy, handles both protocols simultaneously. Implements
 * all SOCKS commands, including UDP relaying.
 * <p>
 * In order to use it you will need to implement ServerAuthenticator interface.
 * There is an implementation of this interface which does no authentication
 * ServerAuthenticatorNone, but it is very dangerous to use, as it will give
 * access to your local network to anybody in the world. One should never use
 * this authentication scheme unless one have pretty good reason to do so. There
 * is a couple of other authentication schemes in socks.server package.
 * 
 * @see socks.server.ServerAuthenticator
 */
public class SocksListener extends Listener {

	private ServerAuthenticator auth;

	/**
	 * Creates a proxy server with given Authentication scheme.
	 * 
	 * @param auth
	 *            Authentication scheme to be used.
	 */
	public SocksListener(int listenPort) throws IOException {
		this(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), listenPort);
	}

	public SocksListener(InetAddress address, int listenPort)
			throws IOException {
		super(address, listenPort);
	}

	public void setAuthenticator(ServerAuthenticator authenticator) {
		this.auth = authenticator;
	}

	@Override
	protected ConnectionHandler createConnectionHandler(Socket socket)
			throws IOException {
		SocksProtocol sp = new SocksProtocol(socket, auth);
		sp.handleConnectRequest();

		String host = sp.getTargetHost();
		int port = sp.getTargetPort();
		ConnectionHandler ch = super.createConnectionHandler(socket);
		ch.setTarget(false, host, port);
		return ch;
	}

	private static class SocksProtocol {

		private Socket socket;

		private InputStream in;

		private OutputStream out;

		private ProxyMessage msg;

		private ServerAuthenticator auth;

		public SocksProtocol(Socket accept, ServerAuthenticator auth) {
			this.socket = accept;
			if (auth == null) {
				this.auth = new ServerAuthenticatorNone();
			} else {
				this.auth = auth;
			}
		}

		public void handleConnectRequest() throws IOException {
			try {
				startSession();
			} catch (IOException ioe) {
				handleException(ioe);
				throw ioe;
			}
		}

		private void startSession() throws IOException {
			auth = auth.startSession(socket);

			if (auth == null) { // Authentication failed
				throw new SocksException(SocksConstants.SOCKS_AUTH_FAILURE);
			}

			in = auth.getInputStream();
			out = auth.getOutputStream();

			msg = readMsg(in);
			handleRequest(msg);
		}

		private void handleException(IOException ioe) {
			// If we couldn't read the request, return;
			if (msg == null)
				return;
			int error_code = SocksConstants.SOCKS_FAILURE;

			if (ioe instanceof SocksException)
				error_code = ((SocksException) ioe).getErrorCode();
			else if (ioe instanceof NoRouteToHostException)
				error_code = SocksConstants.SOCKS_HOST_UNREACHABLE;
			else if (ioe instanceof ConnectException)
				error_code = SocksConstants.SOCKS_CONNECTION_REFUSED;
			else if (ioe instanceof InterruptedIOException)
				error_code = SocksConstants.SOCKS_TTL_EXPIRE;

			if (error_code > SocksConstants.SOCKS_ADDR_NOT_SUPPORTED
					|| error_code < 0) {
				error_code = SocksConstants.SOCKS_FAILURE;
			}

			sendErrorMessage(error_code);
		}

		private void sendErrorMessage(int error_code) {
			ProxyMessage err_msg;
			if (msg instanceof Socks4Message)
				err_msg = new Socks4Message(Socks4Message.REPLY_REJECTED);
			else
				err_msg = new Socks5Message(error_code);
			try {
				err_msg.write(out);
			} catch (IOException ioe) {
			}
		}

		private ProxyMessage readMsg(InputStream in) throws IOException {
			PushbackInputStream push_in;
			if (in instanceof PushbackInputStream)
				push_in = (PushbackInputStream) in;
			else
				push_in = new PushbackInputStream(in);

			int version = push_in.read();
			push_in.unread(version);

			ProxyMessage msg;

			if (version == 5) {
				msg = new Socks5Message(push_in, false);
			} else if (version == 4) {
				msg = new Socks4Message(push_in, false);
			} else {
				throw new SocksException(SocksConstants.SOCKS_FAILURE);
			}
			return msg;
		}

		private void handleRequest(ProxyMessage msg) throws IOException {
			if (!auth.checkRequest(msg))
				throw new SocksException(SocksConstants.SOCKS_FAILURE);

			if (msg.ip == null) {
				if (msg instanceof Socks5Message) {
					msg.ip = InetAddress.getByName(msg.host);
				} else
					throw new SocksException(SocksConstants.SOCKS_FAILURE);
			}

			switch (msg.command) {
			case SocksConstants.SOCKS_CMD_CONNECT:
				onConnect(msg);
				break;
			default:
				throw new SocksException(SocksConstants.SOCKS_CMD_NOT_SUPPORTED);
			}
		}

		private void onConnect(ProxyMessage msg) throws IOException {
			ProxyMessage response = null;

			if (msg instanceof Socks5Message) {
				response = new Socks5Message(SocksConstants.SOCKS_SUCCESS,
						msg.ip, msg.port);
			} else {
				response = new Socks4Message(Socks4Message.REPLY_OK, msg.ip,
						msg.port);
			}
			response.write(out);

			targetHost = msg.host;
			targetPort = msg.port;
		}

		private String targetHost = null;

		private int targetPort = -1;

		public String getTargetHost() {
			return targetHost;
		}

		public int getTargetPort() {
			return targetPort;
		}

	}

	public static void main(String[] args) throws Exception {
		Listener l = new SocksListener(InetAddress.getByAddress(new byte[] {
				127, 0, 0, 1 }), 9997);
		l.setProxyMonitor(new LoggingProxyMonitor() {

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
			public boolean responseHeaderReceived(Conversation conversation)
					throws MessageFormatException {
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
				super.wroteResponseToBrowser(conversation);
			}

		});
		l.setCertificateProvider(new DefaultCertificateProvider());
		l.start();

		System.out.println("Socks Listener started, press Enter to exit");

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
