package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.owasp.httpclient.Conversation;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.NamedValue;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.dao.MessageDAO;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;
import org.owasp.proxy.model.ConversationSummary;
import org.springframework.dao.DataAccessException;

public class ConversationServiceHttpRequestHandler implements
		HttpRequestHandler {

	private static final byte[] SUCCESS_XML = AsciiString
			.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: text/xml\r\n\r\n");
	private static final byte[] SUCCESS_OCTET = AsciiString
			.getBytes("HTTP/1.0 200 Ok\r\nContent-Type: application/octet-stream\r\n\r\n");

	private static final String CONVERSATIONS = "/conversations";
	private static final String SUMMARIES = "/summaries";
	private static final String SUMMARY = "/summary";
	private static final String REQUEST_HEADER = "/requestHeader";
	private static final String RESPONSE_HEADER = "/responseHeader";
	private static final String REQUEST_CONTENT = "/requestContent";
	private static final String RESPONSE_CONTENT = "/responseContent";

	private String hostname;
	private MessageDAO dao;
	private HttpRequestHandler next;

	public ConversationServiceHttpRequestHandler(String hostname,
			MessageDAO dao, HttpRequestHandler next) {
		this.hostname = hostname;
		this.dao = dao;
		this.next = next;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		if (next != null)
			next.dispose();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	public StreamingResponse handleRequest(InetAddress source,
			StreamingRequest request) throws IOException,
			MessageFormatException {
		if (next == null
				|| (hostname != null && hostname.equals(request.getTarget()
						.getHostName()))) {
			return handleLocalRequest(request);
		}
		return next.handleRequest(source, request);
	}

	private StreamingResponse handleLocalRequest(StreamingRequest request) {
		try {
			String resource = request.getResource();
			int q = resource.indexOf('?');
			NamedValue[] parameters = null;
			if (q > -1) {
				parameters = NamedValue.parse(resource.substring(q + 1), "&",
						"=");
				resource = resource.substring(0, q);
			}
			if (resource.equals(CONVERSATIONS)) {
				String since = NamedValue.findValue(parameters, "since");
				if (since != null)
					return listConversations(Integer.parseInt(since));
				return listConversations(0);
			} else if (resource.equals(SUMMARIES)) {
				String since = NamedValue.findValue(parameters, "since");
				if (since != null)
					return getSummaries(Integer.parseInt(since));
				return getSummaries(0);
			} else if (resource.equals(SUMMARY)) {
				String id = NamedValue.findValue(parameters, "id");
				if (id != null)
					return getSummary(Integer.parseInt(id));
			} else if (resource.equals(REQUEST_HEADER)) {
				String id = NamedValue.findValue(parameters, "id");
				if (id != null)
					return getRequestHeader(Integer.parseInt(id));
			} else if (resource.equals(RESPONSE_HEADER)) {
				String id = NamedValue.findValue(parameters, "id");
				if (id != null)
					return getResponseHeader(Integer.parseInt(id));
			} else if (resource.equals(REQUEST_CONTENT)) {
				String id = NamedValue.findValue(parameters, "id");
				String decode = NamedValue.findValue(parameters, "decode");
				if (id != null)
					return getRequestContent(Integer.parseInt(id), "true"
							.equals(decode));
			} else if (resource.equals(RESPONSE_CONTENT)) {
				String id = NamedValue.findValue(parameters, "id");
				String decode = NamedValue.findValue(parameters, "decode");
				if (id != null)
					return getResponseContent(Integer.parseInt(id), "true"
							.equals(decode));
			}
		} catch (MessageFormatException mfe) {
			mfe.printStackTrace();
			return err_400();
		} catch (DataAccessException dae) {
			dae.printStackTrace();
			return err_500();
		} catch (NumberFormatException nfe) {
			nfe.printStackTrace();
			return err_400();
		}
		return err_404();
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

		cs.setTarget(reqH.getTarget());
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

	private StreamingResponse listConversations(int since) {
		Iterator<Integer> it = dao.listConversationsSince(since).iterator();
		StringBuilder buff = new StringBuilder();
		buff.append("<conversations>");
		while (it.hasNext()) {
			buff.append("<conversation>").append(it.next()).append(
					"</conversation>");
		}
		buff.append("</conversations>");
		return successXML(buff.toString());
	}

	private StreamingResponse getSummary(int id) {
		ConversationSummary summary = loadConversationSummary(id);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		xml(buff, summary);
		buff.append("</summaries>");
		return successXML(buff.toString());
	}

	private StreamingResponse getSummaries(int since) {
		Iterator<Integer> ids = dao.listConversationsSince(since).iterator();
		Iterator<ConversationSummary> it = getConversationSummaries(ids);
		StringBuilder buff = new StringBuilder();
		buff.append("<summaries>");
		while (it.hasNext()) {
			xml(buff, it.next());
		}
		buff.append("</summaries>");
		return successXML(buff.toString());
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
		tag(buff, "host", summary.getTarget().getHostName());
		tag(buff, "port", summary.getTarget().getPort());
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

	private StreamingResponse getRequestHeader(int id)
			throws MessageFormatException {
		RequestHeader r = dao.loadRequestHeader(id);
		if (r == null)
			return err_404();

		return successOctet(r.getHeader());
	}

	private StreamingResponse getResponseHeader(int id)
			throws MessageFormatException {
		ResponseHeader r = dao.loadResponseHeader(id);
		if (r == null)
			return err_404();

		return successOctet(r.getHeader());
	}

	private StreamingResponse getRequestContent(int id, boolean decode)
			throws MessageFormatException {
		int contentId = dao.getMessageContentId(id);
		if (contentId == -1)
			return err_404();

		byte[] content = dao.loadMessageContent(contentId);
		if (decode) {
			RequestHeader request = dao.loadRequestHeader(id);
			return successOctet(MessageUtils.decode(request,
					new ByteArrayInputStream(content)));
		}
		return successOctet(content);
	}

	private StreamingResponse getResponseContent(int id, boolean decode)
			throws MessageFormatException {
		int contentId = dao.getMessageContentId(id);
		if (contentId == -1)
			return err_404();

		byte[] content = dao.loadMessageContent(contentId);
		if (decode) {
			ResponseHeader response = dao.loadResponseHeader(id);
			return successOctet(MessageUtils.decode(response,
					new ByteArrayInputStream(content)));
		}
		return successOctet(content);
	}

	private StreamingResponse err_400() {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(AsciiString
				.getBytes("HTTP/1.0 400 Bad request\r\n\r\n"));
		response.setContent(content("Bad request"));
		return response;
	}

	private StreamingResponse err_404() {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(AsciiString
				.getBytes("HTTP/1.0 404 Resource not found\r\n\r\n"));
		response.setContent(content("Resource not found"));
		return response;
	}

	private StreamingResponse err_500() {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(AsciiString
				.getBytes("HTTP/1.0 500 Error processing request\r\n\r\n"));
		response.setContent(content("Error processing request"));
		return response;
	}

	private StreamingResponse successXML(String content) {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(SUCCESS_XML);
		response.setContent(content(content));
		return response;
	}

	private StreamingResponse successOctet(byte[] content) {
		return successOctet(new ByteArrayInputStream(content));
	}

	private StreamingResponse successOctet(InputStream content) {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(SUCCESS_OCTET);
		response.setContent(content);
		return response;
	}

	private InputStream content(byte[] content) {
		return new ByteArrayInputStream(content);
	}

	private InputStream content(String content) {
		return content(AsciiString.getBytes(content));
	}

}
