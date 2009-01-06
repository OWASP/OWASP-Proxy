package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.PrintStream;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

public class LoggingProxyMonitor extends ProxyMonitor {

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

	@Override
	public Response errorFetchingResponseHeader(Request request, Exception e)
			throws MessageFormatException {
		try {
			System.err.println("Error fetching response header: \n");
			System.err.write(request.getMessage());
			e.printStackTrace(new PrintStream(System.err));
		} catch (IOException ioe) {
		}
		return null;
	}

	@Override
	public Response errorFetchingResponseContent(Conversation conversation,
			Exception e) throws MessageFormatException {
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
	public void errorWritingResponseToBrowser(Conversation conversation,
			Exception e) throws MessageFormatException {
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
	public void wroteResponseToBrowser(Conversation conversation)
			throws MessageFormatException {
		try {
			int resp = conversation.getResponse().getMessage().length;
			long time = conversation.getResponseContentTime()
					- conversation.getRequestTime();

			Request request = conversation.getRequest();
			StringBuilder buff = new StringBuilder();
			buff.append(request.getMethod()).append(" ");
			buff.append(request.isSsl() ? "ssl " : "");
			buff.append(request.getHost()).append(":")
					.append(request.getPort());
			buff.append(request.getResource()).append(" ");
			buff.append(conversation.getResponse().getStatus()).append(" - ")
					.append(resp);
			buff.append(" bytes in ").append(time).append("(").append(
					resp / (time * 1000));
			buff.append(" bps)");
			System.out.println(buff.toString());
		} catch (MessageFormatException mfe) {
		}
	}

}
