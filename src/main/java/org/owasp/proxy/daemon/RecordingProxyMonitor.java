package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.owasp.httpclient.Conversation;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.dao.MessageDAO;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.ConversationSummary;
import org.springframework.dao.DataAccessException;

public class RecordingProxyMonitor implements ProxyMonitor {

	private static final Response ERR_400;
	private static final Response ERR_404;
	private static final Response ERR_500;
	private static final byte[] SUCCESS_XML;
	private static final byte[] SUCCESS_OCTET;

	private ThreadLocal<Long> requestTime = new ThreadLocal<Long>();

	static {
		ERR_400 = new Response.Impl();
		ERR_400.setHeader("HTTP/1.0 400 Bad request\r\n\r\n".getBytes());
		ERR_400.setContent("Bad request".getBytes());
		ERR_404 = new Response.Impl();
		ERR_404.setHeader("HTTP/1.0 404 Resource not found\r\n\r\n".getBytes());
		ERR_404.setContent("Resource not found".getBytes());
		ERR_500 = new Response.Impl();
		ERR_500.setHeader("HTTP/1.0 500 Error processing request\r\n\r\n"
				.getBytes());
		ERR_500.setContent("Error processing request".getBytes());
		SUCCESS_XML = AsciiString
				.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: text/xml\r\n\r\n");
		SUCCESS_OCTET = AsciiString
				.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: application/octet-stream\r\n");
	}

	private MessageDAO dao;

	private String host;

	public RecordingProxyMonitor(MessageDAO dao, String host) {
		this.dao = dao;
		this.host = host;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ProxyMonitor#connectionFromClient(java.net.Socket)
	 */
	public void connectionFromClient(Socket socket) {
	}

	public Response requestReceived(Request request) {
		if (!host.equals(request.getHost()))
			return null;
		return handleRequest(request);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ProxyMonitor#errorReadingResponse(org.owasp.httpclient
	 * .Request, org.owasp.httpclient.ResponseHeader, java.lang.Exception)
	 */
	public Response errorReadingResponse(Request request,
			ResponseHeader header, Exception e) {
		requestTime.set(null);
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ProxyMonitor#requestSent(org.owasp.httpclient.
	 * Request)
	 */
	public void requestSent(Request request) {
		requestTime.set(System.currentTimeMillis());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ProxyMonitor#responseReceived(org.owasp.httpclient
	 * .Request, org.owasp.httpclient.ResponseHeader, java.io.InputStream,
	 * java.io.OutputStream)
	 */
	public void responseReceived(Request request, ResponseHeader header,
			InputStream responseContent, OutputStream client)
			throws IOException {
		client.write(header.getHeader());
		try {
			long responseHeaderTime = System.currentTimeMillis();
			CopyInputStream cis = new CopyInputStream(responseContent, client);
			int contentId = dao.saveMessageContent(cis);
			long responseContentTime = System.currentTimeMillis();

			dao.saveRequest(request);
			dao.saveResponseHeader(header, contentId);
			dao.saveConversation(request.getId(), header.getId(), requestTime
					.get(), responseHeaderTime, responseContentTime);
		} catch (DataAccessException dae) {
			dae.printStackTrace();
		}
	}

	private Response handleRequest(Request request) {
		try {
			String resource = request.getResource();
			if (resource.equals("/conversations")) {
				return listConversations(0);
			} else if (resource.startsWith("/conversations?since=")) {
				try {
					int since = Integer.parseInt(resource.substring(21));
					return listConversations(since);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.equals("/summaries")) {
				return getSummaries(0);
			} else if (resource.startsWith("/summaries?since=")) {
				try {
					int since = Integer.parseInt(resource.substring(18));
					return getSummaries(since);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.startsWith("/summary?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(13));
					return getSummary(id);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.startsWith("/requestHeader?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(19));
					return getRequestHeader(id);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.startsWith("/responseHeader?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(20));
					return getResponseHeader(id);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.startsWith("/content?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(20));
					return getContent(id);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			}
		} catch (MessageFormatException mfe) {
			mfe.printStackTrace();
			return ERR_400;
		} catch (DataAccessException dae) {
			dae.printStackTrace();
			return ERR_500;
		}
		return ERR_404;
	}

	private ConversationSummary loadConversationSummary(int id) {
		Conversation c = dao.getConversation(id);
		if (c == null)
			return null;

		RequestHeader reqH = dao.loadRequestHeader(c.getRequestId());
		ResponseHeader respH = dao.loadResponseHeader(c.getResponseId());

		ConversationSummary cs = new ConversationSummary();
		cs.setId(c.getId());
		cs.setRequestTime(c.getRequestTime());
		cs.setResponseHeaderTime(c.getResponseHeaderTime());
		cs.setResponseContentTime(c.getResponseContentTime());

		cs.setHost(reqH.getHost());
		cs.setPort(reqH.getPort());
		cs.setSsl(reqH.isSsl());
		try {
			cs.setRequestMethod(reqH.getMethod());
			cs.setRequestResource(reqH.getResource());
			cs.setRequestContentType(reqH.getHeader("Content-Type"));
		} catch (MessageFormatException mfe) {
			mfe.printStackTrace();
		}
		try {
			cs.setResponseStatus(respH.getStatus());
			cs.setResponseReason(respH.getReason());
			cs.setResponseContentType(respH.getHeader("Content-Type"));
		} catch (MessageFormatException mfe) {
			mfe.printStackTrace();
		}
		int contentId = dao.getMessageContentId(reqH.getId());
		if (contentId != -1)
			cs.setRequestContentSize(dao.getMessageContentSize(contentId));

		contentId = dao.getMessageContentId(respH.getId());
		if (contentId != -1)
			cs.setResponseContentSize(dao.getMessageContentSize(contentId));

		return cs;
	}

	private Iterator<ConversationSummary> getConversationSummaries(
			Iterator<Integer> ids) {
		List<ConversationSummary> conversations = new LinkedList<ConversationSummary>();
		while (ids.hasNext()) {
			conversations.add(loadConversationSummary(ids.next()));
		}
		return conversations.iterator();
	}

	private Response listConversations(int since) {
		Iterator<Integer> it = dao.listConversationsSince(since).iterator();
		StringBuilder buff = new StringBuilder();
		buff.append("<conversations>");
		while (it.hasNext()) {
			buff.append("<conversation>").append(it.next()).append(
					"</conversation>");
		}
		buff.append("</conversations>");
		Response response = new Response.Impl();
		response.setHeader(SUCCESS_XML);
		response.setContent(buff.toString().getBytes());
		return response;
	}

	private Response getSummary(int id) {
		ConversationSummary summary = loadConversationSummary(id);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		xml(buff, summary);
		buff.append("</summaries>");
		Response response = new Response.Impl();
		response.setHeader(SUCCESS_XML);
		response.setContent(buff.toString().getBytes());
		return response;
	}

	private Response getSummaries(int since) {
		Iterator<Integer> ids = dao.listConversationsSince(since).iterator();
		Iterator<ConversationSummary> it = getConversationSummaries(ids);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		while (it.hasNext()) {
			xml(buff, it.next());
		}
		buff.append("</summaries>");
		Response response = new Response.Impl();
		response.setHeader(SUCCESS_XML);
		response.setContent(buff.toString().getBytes());
		return response;
	}

	private void xml(StringBuilder buff, ConversationSummary summary) {
		buff.append("<summary id=\"");
		buff.append(summary.getId());
		buff.append("\" requestTime=\"").append(summary.getRequestTime());
		buff.append("\" responseHeaderTime=\"").append(
				summary.getResponseHeaderTime());
		buff.append("\" responseContentTime=\"").append(
				summary.getResponseContentTime());
		buff.append("\">");
		tag(buff, "host", summary.getHost());
		tag(buff, "port", summary.getPort());
		tag(buff, "ssl", summary.isSsl());
		tag(buff, "resource", summary.getRequestResource());
		tag(buff, "RequestContentType", summary.getRequestContentType());
		tag(buff, "RequestContentSize", summary.getRequestContentSize());
		tag(buff, "status", summary.getResponseStatus());
		tag(buff, "reason", summary.getResponseReason());
		tag(buff, "ResponseContentType", summary.getResponseContentType());
		tag(buff, "RequestContentSize", summary.getRequestContentSize());
		buff.append("</summary>");
	}

	private void tag(StringBuilder buff, String tagname, String content) {
		if (content == null)
			return;
		buff.append("<").append(tagname).append(">");
		buff.append(e(content));
		buff.append("</").append(tagname).append(">");
	}

	private void tag(StringBuilder buff, String tagname, boolean content) {
		buff.append("<").append(tagname).append(">");
		buff.append(content);
		buff.append("</").append(tagname).append(">");
	}

	private void tag(StringBuilder buff, String tagname, int content) {
		if (content <= 0)
			return;
		buff.append("<").append(tagname).append(">");
		buff.append(content);
		buff.append("</").append(tagname).append(">");
	}

	private static String e(String s) {
		StringBuilder buf = new StringBuilder();
		int len = (s == null ? -1 : s.length());

		for (int i = 0; i < len; i++) {
			char c = s.charAt(i);
			if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0'
					&& c <= '9') {
				buf.append(c);
			} else if (c == '<') {
				buf.append("&lt;");
			} else if (c == '>') {
				buf.append("&gt;");
			} else if (c == '\'') {
				buf.append("&apos;");
			} else if (c == '"') {
				buf.append("&quot;");
			} else {
				buf.append("&#" + (int) c + ";");
			}
		}
		return buf.toString();

	}

	private Response getRequestHeader(int id) throws MessageFormatException {
		RequestHeader r = dao.loadRequestHeader(id);
		if (r == null)
			return ERR_404;

		Response response = new Response.Impl();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(r.getHeader());
		return response;
	}

	private Response getResponseHeader(int id) throws MessageFormatException {
		ResponseHeader r = dao.loadResponseHeader(id);
		if (r == null)
			return ERR_404;

		Response response = new Response.Impl();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(r.getHeader());
		return response;
	}

	private Response getContent(int id) throws MessageFormatException {
		int contentId = dao.getMessageContentId(id);
		if (contentId == -1)
			return ERR_404;

		byte[] content = dao.loadMessageContent(contentId);
		Response response = new Response.Impl();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(content);
		return response;
	}

	public Response errorFetchingResponseContent(Conversation conversation,
			Exception e) {
		return null;
	}

	public Response errorFetchingResponseHeader(Request request, Exception e) {
		return null;
	}

	public Response errorReadingRequest(Request request, Exception e) {
		return null;
	}

	public void errorWritingResponseToBrowser(Conversation conversation,
			Exception e) {
	}

	public void responseContentBuffered(Conversation conversation) {
	}

	public boolean responseHeaderReceived(Conversation conversation) {
		return true;
	}

	public void wroteResponseToBrowser(Conversation conversation) {
	}

}
