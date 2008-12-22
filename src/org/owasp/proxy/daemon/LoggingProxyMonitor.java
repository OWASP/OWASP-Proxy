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
			long time = conversation.getResponseBodyTime()
					- conversation.getRequestTime();

			System.out.println(conversation.getRequest().getStartLine() + " : "
					+ conversation.getResponse().getStatus() + " - " + resp
					+ " bytes in " + time + " (" + (resp * 1000 / time)
					+ " bps)");
		} catch (MessageFormatException mfe) {
		}
	}

}
