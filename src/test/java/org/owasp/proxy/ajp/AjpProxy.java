package org.owasp.proxy.ajp;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.owasp.proxy.daemon.ConnectionHandler;
import org.owasp.proxy.daemon.Server;
import org.owasp.proxy.io.LoggingSocketWrapper;

public class AjpProxy {

	public static void main(String[] args) throws Exception {
		if (args == null || args.length != 2) {
			System.out.println("Usage: AjpProxy <host> <port>");
			System.exit(1);
		}
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		DefaultAJPRequestHandler reqHandler = new DefaultAJPRequestHandler();
		reqHandler.setTarget(new InetSocketAddress(host, port));
		ConnectionHandler ch = new AJPConnectionHandler(reqHandler);
		ch = new LoggingConnectionHandler(ch);
		Server s = new Server(new InetSocketAddress("*", 8009), ch);
		s.start();
		System.out.println("Press a key to terminate");
		System.in.read();
		s.stop();
		System.out.println("Done");
	}

	private static class LoggingConnectionHandler implements ConnectionHandler {

		private ConnectionHandler delegate;

		public LoggingConnectionHandler(ConnectionHandler delegate) {
			this.delegate = delegate;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.owasp.proxy.daemon.ConnectionHandler#handleConnection(java.net
		 * .Socket)
		 */
		@Override
		public void handleConnection(Socket socket) throws IOException {
			PrintStream dump = System.err;
			String sock = "AJP " + socket.toString();
			socket = new LoggingSocketWrapper(socket, dump, sock + " << ", sock
					+ " >> ");
			delegate.handleConnection(socket);
		}

	}
}
