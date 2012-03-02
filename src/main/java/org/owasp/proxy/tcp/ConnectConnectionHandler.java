package org.owasp.proxy.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.util.logging.Logger;

import org.owasp.proxy.daemon.TargetedConnectionHandler;
import org.owasp.proxy.http.MessageFormatException;
import org.owasp.proxy.http.MessageHeader;
import org.owasp.proxy.http.MessageUtils;
import org.owasp.proxy.http.MutableRequestHeader;
import org.owasp.proxy.http.MutableResponseHeader;
import org.owasp.proxy.http.ResponseHeader;
import org.owasp.proxy.util.Pump;

public class ConnectConnectionHandler implements TargetedConnectionHandler {

	private InetSocketAddress proxy;

	private Logger logger = Logger.getLogger(getClass().toString());
	
	public ConnectConnectionHandler(InetSocketAddress proxy) {
		this.proxy = proxy;
	}

	@Override
	public void handleConnection(Socket client, InetSocketAddress target)
			throws IOException {
		logger.info("Connecting to " + target);
		Socket server = new Socket(Proxy.NO_PROXY);
		server.connect(proxy);
		try {
			doConnect(server, target);
		} catch (MessageFormatException e) {
			server.close();
			throw new IOException("CONNECT error", e);
		} catch (IOException e) {
			server.close();
			throw e;
		}
		Pump.connect(client, server);
	}

	private void doConnect(Socket server, InetSocketAddress target)
			throws IOException, MessageFormatException {
		sendRequest(server.getOutputStream(), target);
		logger.info("Sent CONNECT to " + proxy + " for " + target);
		ResponseHeader resp = readResponse(server.getInputStream());
		logger.info("Got " + resp.getStartLine());
		
		String status = resp.getStatus();
		if (!"200".equals(status))
			throw new IOException("CONNECT refused: " + resp.getStatus() + " " + resp.getReason());
	}

	private void sendRequest(OutputStream out, InetSocketAddress target) throws IOException, MessageFormatException {
		MutableRequestHeader req = new MutableRequestHeader.Impl();
		String resource = target.getAddress().getHostAddress() + ":"
				+ target.getPort();
		req.setMethod("CONNECT");
		req.setResource(resource);
		req.setVersion("HTTP/1.0");
		out.write(req.getHeader());
		out.flush();
	}
	
	private ResponseHeader readResponse(InputStream in) throws IOException,
			MessageFormatException {
		MutableResponseHeader response = new MutableResponseHeader.Impl();
		MessageHeader header = MessageUtils.readHeader(in);
		if (header == null)
			return null;
		response.setHeader(header.getHeader());
		return response;
	}

}
