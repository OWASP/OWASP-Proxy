package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.dao.MessageDAO;
import org.owasp.httpclient.util.MessageUtils;

public class RecordingHttpRequestHandler implements HttpRequestHandler {

	protected MessageDAO dao;

	private HttpRequestHandler next;

	private int max;

	public RecordingHttpRequestHandler(MessageDAO dao, HttpRequestHandler next,
			int maxContentSize) {
		this.dao = dao;
		this.next = next;
		this.max = maxContentSize;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		next.dispose();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	public StreamingResponse handleRequest(final InetAddress source,
			StreamingRequest request) throws IOException,
			MessageFormatException {
		BufferedRequest req = new BufferedRequest.Impl();
		BufferedResponse resp = new BufferedResponse.Impl();
		ConversationObserver observer = new ConversationObserver(source, req,
				resp);
		MessageUtils.delayedCopy(request, req, max, observer
				.getRequestObserver());
		StreamingResponse response = next.handleRequest(source, request);
		MessageUtils.delayedCopy(response, resp, max, observer
				.getResponseObserver());
		return response;
	}

	protected void record(InetAddress source, BufferedRequest request,
			BufferedResponse response, long requestTime,
			long responseHeaderTime, long responseContentTime) {
		dao.saveRequest(request);
		dao.saveResponse(response);
		dao.saveConversation(request.getId(), response.getId(), requestTime,
				responseHeaderTime, responseContentTime);
	}

	private class ConversationObserver {

		private InetAddress source;
		private BufferedRequest request;
		private BufferedResponse response;

		private long requestTime, responseHeaderTime, responseContentTime;

		private boolean requestContentOverflow, responseContentOverflow;

		public ConversationObserver(InetAddress source,
				BufferedRequest request, BufferedResponse response) {
			this.source = source;
			this.request = request;
			this.response = response;
		}

		public MessageUtils.DelayedCopyObserver getRequestObserver() {
			return new MessageUtils.DelayedCopyObserver() {
				@Override
				public void contentOverflow() {
					requestContentOverflow = true;
				}

				@Override
				public void copyCompleted() {
					requestTime = System.currentTimeMillis();
				}
			};
		}

		public MessageUtils.DelayedCopyObserver getResponseObserver() {
			responseHeaderTime = System.currentTimeMillis();
			return new MessageUtils.DelayedCopyObserver() {
				@Override
				public void contentOverflow() {
					responseContentOverflow = true;
				}

				@Override
				public void copyCompleted() {
					responseContentTime = System.currentTimeMillis();
					if (requestContentOverflow)
						request.setContent(null);
					if (responseContentOverflow)
						response.setContent(null);
					record(source, request, response, requestTime,
							responseHeaderTime, responseContentTime);
				}
			};
		}
	}
}
