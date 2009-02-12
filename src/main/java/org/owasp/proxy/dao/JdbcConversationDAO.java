package org.owasp.proxy.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Collection;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.ConversationSummary;
import org.owasp.proxy.model.Message;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcDaoSupport;
import org.springframework.jdbc.core.simple.ParameterizedRowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcTemplate;

public class JdbcConversationDAO extends NamedParameterJdbcDaoSupport implements
		ConversationDAO {

	private static final String SIZE = "size";
	private static final String CONTENT_TYPE = "contentType";
	private static final String RESPONSE_ID = "responseId";
	private static final String REQUEST_ID = "requestId";
	private static final String RESPONSE_CONTENT_TIME = "responseContentTime";
	private static final String RESPONSE_HEADER_TIME = "responseHeaderTime";
	private static final String REQUEST_TIME = "requestTime";
	private static final String RESPONSE_CONTENT_SIZE = "responseContentSize";
	private static final String RESPONSE_CONTENT_TYPE = "responseContentType";
	private static final String RESPONSE_REASON = "responseReason";
	private static final String RESPONSE_STATUS = "responseStatus";
	private static final String REQUEST_CONTENT_SIZE = "requestContentSize";
	private static final String REQUEST_CONTENT_TYPE = "requestContentType";
	private static final String REQUEST_RESOURCE = "requestResource";
	private static final String REQUEST_METHOD = "requestMethod";
	private static final String SSL = "ssl";
	private static final String PORT = "port";
	private static final String HOST = "host";
	private static final String ID = "id";
	private static final String MESSAGE = "message";
	private static final String CONNECTION = "connection";

	private static final ParameterizedRowMapper<Request> REQUEST_MAPPER = new RequestMapper();
	private static final ParameterizedRowMapper<Response> RESPONSE_MAPPER = new ResponseMapper();
	private static final ParameterizedRowMapper<ConversationSummary> CONVERSATIONSUMMARY_MAPPER = new ConversationSummaryMapper();
	private static final ParameterizedRowMapper<Conversation> CONVERSATION_MAPPER = new ConversationMapper();
	private static final ParameterizedRowMapper<Integer> ID_MAPPER = new IdMapper();

	private final static String SELECT_CONVERSATIONS = "SELECT id FROM conversations WHERE id > :id ORDER BY id";

	private final static String SELECT_SEQUENCE = "SELECT NEXT VALUE FOR ids";

	private final static String INSERT_REQUEST = "INSERT INTO requests (id, host, port, ssl) VALUES (:id, :host, :port, :ssl)";

	private final static String INSERT_MESSAGE = "INSERT INTO MESSAGES (id, message, contentType, size) VALUES (:id, :message, :contentType, :size)";

	private final static String SELECT_REQUEST = "SELECT requests.id AS id, host, port, ssl, message FROM requests, messages WHERE requests.id = messages.id AND messages.id = :id";

	private final static String SELECT_RESPONSE = "SELECT id, message FROM messages WHERE id = :id";

	private final static String SELECT_REQUEST_BY_CONVERSATION = "SELECT requests.id AS id, host, port, ssl, message FROM conversations, requests, messages WHERE requests.id = messages.id AND messages.id = conversations.requestId AND conversations.id = :id";

	private final static String SELECT_RESPONSE_BY_CONVERSATION = "SELECT messages.id AS ID, message FROM conversations, messages WHERE conversations.responseId = messages.id AND conversations.id = :id";

	private final static String INSERT_CONVERSATION = "INSERT INTO conversations (id, requestId, responseId, requestMethod, requestResource, responseStatus, responseReason, requestTime, responseHeaderTime, responseContentTime, connection) VALUES (:id, :requestId, :responseId, :requestMethod, :requestResource, :responseStatus, :responseReason, :requestTime, :responseHeaderTime, :responseContentTime, :connection)";

	private final static String SELECT_CONVERSATION_SUMMARY = "SELECT conversations.id AS id, requests.host AS host, requests.port AS port, "
			+ "requests.ssl AS ssl, requestMethod, requestResource, requestmessage.contentType AS requestContentType, "
			+ "requestmessage.size AS requestContentSize, responseStatus, responseReason, "
			+ "responsemessage.contentType AS responseContentType, responseMessage.size AS responseContentSize, "
			+ "requestTime, responseHeaderTime, responseContentTime, connection "
			+ "FROM conversations, requests, messages AS requestmessage, messages AS responsemessage "
			+ "WHERE conversations.id = :id AND conversations.requestId = requestMessage.id AND conversations.responseId = responsemessage.id";

	private final static String SELECT_CONVERSATION = "SELECT id, requestTime, responseHeaderTime, responseContentTime, connection "
			+ "FROM conversations WHERE conversations.id = :id";

	private final static String CREATE_SEQUENCE = "CREATE SEQUENCE ids";

	private final static String CREATE_MESSAGES = "CREATE TABLE messages ("
			+ "id INTEGER NOT NULL," + "contentType VARCHAR(256), "
			+ "size INTEGER, " + "message LONGVARBINARY NOT NULL" + ")";

	private final static String CREATE_REQUESTS = "CREATE TABLE requests ("
			+ "id INTEGER NOT NULL," + "host VARCHAR(255) NOT NULL,"
			+ "port INTEGER NOT NULL," + "ssl BIT" + ")";

	private final static String CREATE_CONVERSATIONS = "CREATE TABLE conversations ("
			+ "id INTEGER NOT NULL,"
			+ "requestId INTEGER NOT NULL,"
			+ "responseId INTEGER,"
			+ "requestMethod VARCHAR(255),"
			+ "requestResource LONGVARCHAR,"
			+ "responseStatus CHAR(3),"
			+ "responseReason VARCHAR(255),"
			+ "requestTime TIMESTAMP,"
			+ "responseHeaderTime TIMESTAMP,"
			+ "responseContentTime TIMESTAMP,"
			+ "connection VARCHAR(255)"
			+ ")";

	private int getNextId() {
		return getJdbcTemplate().queryForInt(SELECT_SEQUENCE);
	}

	public void createTables() {
		JdbcTemplate template = getJdbcTemplate();
		template.execute(CREATE_SEQUENCE);
		template.execute(CREATE_MESSAGES);
		template.execute(CREATE_REQUESTS);
		template.execute(CREATE_CONVERSATIONS);
	}

	public Collection<Integer> listConversations() throws DataAccessException {
		return listConversationsAfter(0);
	}

	public Collection<Integer> listConversationsAfter(int id)
			throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.query(SELECT_CONVERSATIONS, ID_MAPPER, params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	public void saveConversation(Conversation conversation)
			throws DataAccessException {
		conversation.setId(getNextId());

		Request request = conversation.getRequest();
		saveRequest(request);

		Response response = conversation.getResponse();
		saveResponse(response);

		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, conversation.getId(), Types.INTEGER);
		params.addValue(REQUEST_ID, request.getId(), Types.INTEGER);
		params.addValue(RESPONSE_ID, response.getId(), Types.INTEGER);
		params.addValue(REQUEST_TIME, new Timestamp(conversation
				.getRequestTime()), Types.TIMESTAMP);
		params.addValue(RESPONSE_HEADER_TIME, new Timestamp(conversation
				.getResponseHeaderTime()), Types.TIMESTAMP);
		params.addValue(RESPONSE_CONTENT_TIME, new Timestamp(conversation
				.getResponseContentTime()), Types.TIMESTAMP);
		params
				.addValue(CONNECTION, conversation.getConnection(),
						Types.VARCHAR);

		try {
			params.addValue(REQUEST_METHOD, request.getMethod(),
					Types.LONGVARCHAR);
			params.addValue(REQUEST_RESOURCE, request.getResource(),
					Types.LONGVARCHAR);
		} catch (MessageFormatException mfe) {
			params.addValue(REQUEST_METHOD, null, Types.LONGVARCHAR);
			params.addValue(REQUEST_RESOURCE, null, Types.LONGVARCHAR);
		}
		try {
			params.addValue(RESPONSE_STATUS, response.getStatus(),
					Types.LONGVARCHAR);
			params.addValue(RESPONSE_REASON, response.getReason(),
					Types.LONGVARCHAR);
		} catch (MessageFormatException mfe) {
			params.addValue(RESPONSE_STATUS, null, Types.LONGVARCHAR);
			params.addValue(RESPONSE_REASON, null, Types.LONGVARCHAR);
		}

		getNamedParameterJdbcTemplate().update(INSERT_CONVERSATION, params);
	}

	public Conversation findConversation(int id) throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, id, Types.INTEGER);
		SimpleJdbcTemplate template = new SimpleJdbcTemplate(
				getNamedParameterJdbcTemplate());
		try {
			Conversation c = template.queryForObject(SELECT_CONVERSATION,
					CONVERSATION_MAPPER, params);
			c.setRequest(loadRequestForConversation(id));
			c.setResponse(loadResponseForConversation(id));
			return c;
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	public ConversationSummary findConversationSummary(int id)
			throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, id, Types.INTEGER);
		SimpleJdbcTemplate template = new SimpleJdbcTemplate(
				getNamedParameterJdbcTemplate());
		return template.queryForObject(SELECT_CONVERSATION_SUMMARY,
				CONVERSATIONSUMMARY_MAPPER, params);
	}

	public Request findRequest(int id) throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		try {
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_REQUEST, REQUEST_MAPPER,
					params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	private Request loadRequestForConversation(int id) {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_REQUEST_BY_CONVERSATION,
					REQUEST_MAPPER, params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	public Response findResponse(int id) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_RESPONSE, RESPONSE_MAPPER,
					params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	private Response loadResponseForConversation(int id)
			throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_RESPONSE_BY_CONVERSATION,
					RESPONSE_MAPPER, params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	public void saveRequest(Request request) throws DataAccessException {
		if (request.getHost() == null)
			throw new NullPointerException("host parameter may not be null!");
		saveMessage(request);
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, request.getId(), Types.INTEGER);
		params.addValue(HOST, request.getHost(), Types.VARCHAR);
		params.addValue(PORT, request.getPort(), Types.INTEGER);
		params.addValue(SSL, request.isSsl(), Types.BIT);
		getNamedParameterJdbcTemplate().update(INSERT_REQUEST, params);
	}

	public void saveResponse(Response response) throws DataAccessException {
		saveMessage(response);
	}

	private void saveMessage(Message message) {
		message.setId(getNextId());
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, message.getId(), Types.INTEGER);
		try {
			params.addValue(CONTENT_TYPE, message.getHeader("Content-Type"),
					Types.LONGVARCHAR);
		} catch (MessageFormatException mfe) {
			params.addValue(CONTENT_TYPE, null, Types.LONGVARCHAR);
		}
		try {
			byte[] content = message.getContent();
			params.addValue(SIZE, content == null ? 0 : content.length,
					Types.INTEGER);
		} catch (MessageFormatException mfe) {
			params.addValue(SIZE, 0, Types.INTEGER);
		}
		params.addValue(MESSAGE, message.getMessage(), Types.VARBINARY);
		getNamedParameterJdbcTemplate().update(INSERT_MESSAGE, params);
	}

	public boolean deleteConversation(int id) throws DataAccessException {

		return false;
	}

	private static class ConversationMapper implements
			ParameterizedRowMapper<Conversation> {

		public Conversation mapRow(ResultSet rs, int rowNum)
				throws SQLException {
			int id = rs.getInt(ID);
			Timestamp t;
			long requestTime = 0, responseHeaderTime = 0, responseContentTime = 0;
			if ((t = rs.getTimestamp(REQUEST_TIME)) != null)
				requestTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_HEADER_TIME)) != null)
				responseHeaderTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_CONTENT_TIME)) != null)
				responseContentTime = t.getTime();

			Conversation c = new Conversation();
			c.setId(id);
			c.setRequestTime(requestTime);
			c.setResponseHeaderTime(responseHeaderTime);
			c.setResponseContentTime(responseContentTime);
			c.setConnection(rs.getString(CONNECTION));
			return c;
		}

	}

	private static class ConversationSummaryMapper implements
			ParameterizedRowMapper<ConversationSummary> {

		public ConversationSummary mapRow(ResultSet rs, int rowNum)
				throws SQLException {
			ConversationSummary cs = new ConversationSummary();
			cs.setId(rs.getInt(ID));

			Timestamp t;
			long requestTime = 0, responseHeaderTime = 0, responseContentTime = 0;
			if ((t = rs.getTimestamp(REQUEST_TIME)) != null)
				requestTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_HEADER_TIME)) != null)
				responseHeaderTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_CONTENT_TIME)) != null)
				responseContentTime = t.getTime();
			cs.setRequestTime(requestTime);
			cs.setResponseHeaderTime(responseHeaderTime);
			cs.setResponseContentTime(responseContentTime);
			cs.setConnection(rs.getString(CONNECTION));

			cs.setHost(rs.getString(HOST));
			cs.setPort(rs.getInt(PORT));
			cs.setSsl(rs.getBoolean(SSL));
			cs.setRequestMethod(rs.getString(REQUEST_METHOD));
			cs.setRequestResource(rs.getString(REQUEST_RESOURCE));
			cs.setRequestContentType(rs.getString(REQUEST_CONTENT_TYPE));
			cs.setRequestContentSize(rs.getInt(REQUEST_CONTENT_SIZE));

			cs.setResponseStatus(rs.getString(RESPONSE_STATUS));
			cs.setResponseReason(rs.getString(RESPONSE_REASON));
			cs.setResponseContentType(rs.getString(RESPONSE_CONTENT_TYPE));
			cs.setResponseContentSize(rs.getInt(RESPONSE_CONTENT_SIZE));

			return cs;
		}

	}

	private static class RequestMapper implements
			ParameterizedRowMapper<Request> {

		public Request mapRow(ResultSet rs, int rowNum) throws SQLException {
			int id = rs.getInt(ID);

			String host = rs.getString(HOST);
			int port = rs.getInt(PORT);
			boolean ssl = rs.getBoolean(SSL);

			Request request = new Request();
			request.setId(id);
			request.setHost(host);
			request.setPort(port);
			request.setSsl(ssl);
			request.setMessage(rs.getBytes(MESSAGE));
			return request;
		}

	}

	private static class ResponseMapper implements
			ParameterizedRowMapper<Response> {

		public Response mapRow(ResultSet rs, int rowNum) throws SQLException {
			int id = rs.getInt(ID);

			Response response = new Response();
			response.setId(id);
			response.setMessage(rs.getBytes(MESSAGE));
			return response;
		}

	}

	private static class IdMapper implements ParameterizedRowMapper<Integer> {

		public Integer mapRow(ResultSet rs, int rowNum) throws SQLException {
			return Integer.valueOf(rs.getInt(ID));
		}
	}
}
