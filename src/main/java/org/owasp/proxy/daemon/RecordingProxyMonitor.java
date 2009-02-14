package org.owasp.proxy.daemon;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.proxy.dao.ConversationDAO;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.ConversationSummary;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.springframework.dao.DataAccessException;

public class RecordingProxyMonitor extends DefaultProxyMonitor {

	private static final Response ERR_400;
	private static final Response ERR_404;
	private static final Response ERR_500;
	private static final byte[] SUCCESS_XML;
	private static final byte[] SUCCESS_OCTET;

	static {
		ERR_400 = new Response();
		ERR_400.setHeader("HTTP/1.0 400 Bad request\r\n\r\n".getBytes());
		ERR_400.setContent("Bad request".getBytes());
		ERR_404 = new Response();
		ERR_404.setHeader("HTTP/1.0 404 Resource not found\r\n\r\n".getBytes());
		ERR_404.setContent("Resource not found".getBytes());
		ERR_500 = new Response();
		ERR_500.setHeader("HTTP/1.0 500 Error processing request\r\n\r\n"
				.getBytes());
		ERR_500.setContent("Error processing request".getBytes());
		SUCCESS_XML = AsciiString
				.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: text/xml\r\n\r\n");
		SUCCESS_OCTET = AsciiString
				.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: application/octet-stream\r\n");
	}

	private ConversationDAO dao;

	private String host;

	public RecordingProxyMonitor(ConversationDAO conversationDao, String host) {
		this.dao = conversationDao;
		this.host = host;
	}

	@Override
	public Response requestReceived(Request request) {
		if (!host.equals(request.getHost()))
			return super.requestReceived(request);
		return handleRequest(request);
	}

	@Override
	public void conversationCompleted(Conversation conversation) {
		recordConversation(conversation);
		super.conversationCompleted(conversation);
	}

	private void recordConversation(Conversation conversation) {
		try {
			dao.saveConversation(conversation);
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
			} else if (resource.startsWith("/request?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(13));
					return getRequest(id);
				} catch (NumberFormatException nfe) {
					return ERR_400;
				}
			} else if (resource.startsWith("/response?id=")) {
				try {
					int id = Integer.parseInt(resource.substring(14));
					return getResponse(id);
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

	private Iterator<ConversationSummary> getConversationSummaries(
			Iterator<Integer> ids) {
		List<ConversationSummary> conversations = new LinkedList<ConversationSummary>();
		while (ids.hasNext()) {
			conversations.add(dao.findConversationSummary(ids.next()));
		}
		return conversations.iterator();
	}

	private Response listConversations(int since) {
		Iterator<Integer> it = dao.listConversationsAfter(since).iterator();
		StringBuilder buff = new StringBuilder();
		buff.append("<conversations>");
		while (it.hasNext()) {
			buff.append("<conversation>").append(it.next()).append(
					"</conversation>");
		}
		buff.append("</conversations>");
		Response response = new Response();
		response.setHeader(SUCCESS_XML);
		response.setContent(buff.toString().getBytes());
		return response;
	}

	private Response getSummary(int id) {
		ConversationSummary summary = dao.findConversationSummary(id);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		xml(buff, summary);
		buff.append("</summaries>");
		Response response = new Response();
		response.setHeader(SUCCESS_XML);
		response.setContent(buff.toString().getBytes());
		return response;
	}

	private Response getSummaries(int since) {
		Iterator<Integer> ids = dao.listConversationsAfter(since).iterator();
		Iterator<ConversationSummary> it = getConversationSummaries(ids);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		while (it.hasNext()) {
			xml(buff, it.next());
		}
		buff.append("</summaries>");
		Response response = new Response();
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

	private Response getRequest(int id) throws MessageFormatException {
		Request r = dao.findRequest(id);
		Response response = new Response();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(r.getMessage());
		return response;
	}

	private Response getResponse(int id) throws MessageFormatException {
		Response r = dao.findResponse(id);
		Response response = new Response();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(r.getMessage());
		return response;
	}
}
