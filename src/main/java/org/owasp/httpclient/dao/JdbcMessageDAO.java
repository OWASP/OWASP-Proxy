package org.owasp.httpclient.dao;

import java.io.InputStream;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Collection;
import java.util.Collections;

import org.owasp.httpclient.Conversation;
import org.owasp.httpclient.MessageHeader;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.io.CountingInputStream;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcDaoSupport;
import org.springframework.jdbc.core.simple.ParameterizedRowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;

public class JdbcMessageDAO extends NamedParameterJdbcDaoSupport implements
		MessageDAO {

	private static final String SSL = "ssl";
	private static final String PORT = "port";
	private static final String HOST = "host";
	private static final String ID = "id";
	private static final String HEADER = "header";
	private static final String SIZE = "size";
	private static final String CONTENT = "content";
	private static final String CONTENTID = "contentId";
	private static final String REQUESTID = "requestId";
	private static final String RESPONSEID = "responseId";
	private static final String REQUEST_TIME = "requestTime";
	private static final String RESPONSE_HEADER_TIME = "responseHeaderTime";
	private static final String RESPONSE_CONTENT_TIME = "responseContentTime";

	private static final ParameterizedRowMapper<Request> REQUEST_MAPPER = new RequestMapper();
	private static final ParameterizedRowMapper<Response> RESPONSE_MAPPER = new ResponseMapper();
	private static final ParameterizedRowMapper<byte[]> CONTENT_MAPPER = new ContentMapper();
	private static final ParameterizedRowMapper<Integer> ID_MAPPER = new IdMapper();
	private static final ParameterizedRowMapper<Conversation> CONVERSATION_MAPPER = new ConversationMapper();

	private final static String INSERT_CONTENT = "INSERT INTO contents (content, size) VALUES (:content, :size)";

	private final static String UPDATE_CONTENT_SIZE = "UPDATE contents SET size = :size";

	private final static String SELECT_CONTENT = "SELECT content FROM contents WHERE id = :id";

	private final static String SELECT_CONTENT_SIZE = "SELECT size FROM contents WHERE id = :id";

	private final static String INSERT_HEADER = "INSERT INTO headers (header, contentId) VALUES (:header, :contentId)";

	private final static String SELECT_HEADER = "SELECT id, header FROM headers WHERE id = :id";

	private final static String SELECT_CONTENT_ID = "SELECT contentId FROM headers WHERE id = :id";

	private final static String INSERT_REQUEST = "INSERT INTO requests (id, host, port, ssl) VALUES (:id, :host, :port, :ssl)";

	private final static String SELECT_REQUEST = "SELECT requests.id AS id, host, port, ssl, header FROM requests, headers WHERE requests.id = headers.id AND headers.id = :id";

	private final static String INSERT_CONVERSATION = "INSERT INTO conversations (requestId, responseId, requestTime, responseHeaderTime, responseContentTime) VALUES (:requestId, :responseId, :requestTime, :responseHeaderTime, :responseContentTime)";

	private final static String DELETE_CONVERSATION = "DELETE FROM conversations WHERE id = :id";

	private final static String SELECT_SUMMARY = "SELECT id, requestId, responseId, requestTime, responseHeaderTime, responseContentTime FROM conversations WHERE id = :id";

	private final static String SELECT_CONVERSATIONS = "SELECT id FROM conversations WHERE id > :id";

	private final static String CREATE_CONTENTS_TABLE = "CREATE TABLE contents ("
			+ "id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			+ "content LONGVARBINARY NOT NULL," + "size INTEGER NOT NULL)";

	private final static String CREATE_HEADERS_TABLE = "CREATE TABLE headers ("
			+ "id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			+ "header LONGVARBINARY NOT NULL,"
			+ "contentId INTEGER,"
			+ "CONSTRAINT content_fk FOREIGN KEY (contentId) REFERENCES contents(id) ON DELETE CASCADE)";

	private final static String CREATE_REQUESTS_TABLE = "CREATE TABLE requests ("
			+ "id INTEGER NOT NULL PRIMARY KEY,"
			+ "host VARCHAR(255) NOT NULL,"
			+ "port INTEGER NOT NULL,"
			+ "ssl BIT NOT NULL,"
			+ "CONSTRAINT header_fk FOREIGN KEY (id) REFERENCES headers(id) ON DELETE CASCADE)";

	private final static String CREATE_CONVERSATIONS_TABLE = "CREATE TABLE conversations ("
			+ "id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			+ "requestId INTEGER NOT NULL,"
			+ "responseId INTEGER NOT NULL,"
			+ "requestTime TIMESTAMP, "
			+ "responseHeaderTime TIMESTAMP, "
			+ "responseContentTime TIMESTAMP, "
			+ "CONSTRAINT request_fk FOREIGN KEY (requestId) REFERENCES requests(id) ON DELETE CASCADE,"
			+ "CONSTRAINT response_fk FOREIGN KEY (responseId) REFERENCES headers(id) ON DELETE CASCADE)";

	public void createTables() throws DataAccessException {
		JdbcTemplate template = getJdbcTemplate();
		template.execute(CREATE_CONTENTS_TABLE);
		template.execute(CREATE_HEADERS_TABLE);
		template.execute(CREATE_REQUESTS_TABLE);
		template.execute(CREATE_CONVERSATIONS_TABLE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#addConversation(int, int)
	 */
	public int saveConversation(int requestId, int responseId,
			long requestTime, long responseHeaderTime, long responseContentTime)
			throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(REQUESTID, requestId, Types.INTEGER);
		params.addValue(RESPONSEID, responseId, Types.INTEGER);
		params.addValue(REQUEST_TIME, requestTime == 0 ? null : new Timestamp(
				requestTime), Types.TIMESTAMP);
		params.addValue(RESPONSE_HEADER_TIME, responseHeaderTime == 0 ? null
				: new Timestamp(responseHeaderTime), Types.TIMESTAMP);
		params.addValue(RESPONSE_CONTENT_TIME, responseContentTime == 0 ? null
				: new Timestamp(responseContentTime), Types.TIMESTAMP);

		KeyHolder key = new GeneratedKeyHolder();
		getNamedParameterJdbcTemplate()
				.update(INSERT_CONVERSATION, params, key);
		return key.getKey().intValue();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#deleteConversation(int)
	 */
	public boolean deleteConversation(int id) throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, id, Types.INTEGER);
		return getNamedParameterJdbcTemplate().update(DELETE_CONVERSATION,
				params) > 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#getConversations()
	 */
	public Collection<Integer> listConversations() throws DataAccessException {
		return listConversationsSince(0);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#getConversationsSince(int)
	 */
	public Collection<Integer> listConversationsSince(int id)
			throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		try {
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.query(SELECT_CONVERSATIONS, ID_MAPPER, params);
		} catch (EmptyResultDataAccessException erdae) {
			return Collections.emptyList();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#getMessageContentId(int)
	 */
	public int getMessageContentId(int headerId) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, headerId, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForInt(SELECT_CONTENT_ID, params);
		} catch (EmptyResultDataAccessException erdae) {
			return -1;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#getMessageContentSize(int)
	 */
	public int getMessageContentSize(int id) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForInt(SELECT_CONTENT_SIZE, params);
		} catch (EmptyResultDataAccessException erdae) {
			return -1;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#getRequestId(int)
	 */
	public Conversation getConversation(int id) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_SUMMARY, CONVERSATION_MAPPER,
					params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#loadMessageContent(int)
	 */
	public byte[] loadMessageContent(int id) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_CONTENT, CONTENT_MAPPER,
					params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#loadRequest(int)
	 */
	public Request loadRequest(int id) throws DataAccessException {
		Request request = (Request) loadRequestHeader(id);
		if (request == null)
			return null;
		int contentId = getMessageContentId(id);
		if (contentId > 0)
			request.setContent(loadMessageContent(contentId));
		return request;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#loadRequestHeader(int)
	 */
	public RequestHeader loadRequestHeader(int id) throws DataAccessException {
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#loadResponse(int)
	 */
	public Response loadResponse(int id) throws DataAccessException {
		Response response = (Response) loadResponseHeader(id);
		if (response == null)
			return null;
		int contentId = getMessageContentId(id);
		if (contentId > 0)
			response.setContent(loadMessageContent(contentId));
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#loadResponseHeader(int)
	 */
	public ResponseHeader loadResponseHeader(int id) throws DataAccessException {
		try {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue(ID, id, Types.INTEGER);
			SimpleJdbcTemplate template = new SimpleJdbcTemplate(
					getNamedParameterJdbcTemplate());
			return template.queryForObject(SELECT_HEADER, RESPONSE_MAPPER,
					params);
		} catch (EmptyResultDataAccessException erdae) {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.dao.MessageDAO#saveMessageContent(byte[])
	 */
	public int saveMessageContent(byte[] messageContent)
			throws DataAccessException {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(CONTENT, messageContent, Types.LONGVARBINARY);
		params.addValue(SIZE, messageContent.length, Types.INTEGER);
		KeyHolder key = new GeneratedKeyHolder();
		getNamedParameterJdbcTemplate().update(INSERT_CONTENT, params, key);
		return key.getKey().intValue();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.httpclient.dao.MessageDAO#saveMessageContentAsStream(java.io .
	 * InputStream)
	 */
	public int saveMessageContent(InputStream messageContent)
			throws DataAccessException {
		CountingInputStream cis = new CountingInputStream(messageContent);
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(CONTENT, cis, Types.LONGVARBINARY);
		params.addValue(SIZE, 0, Types.INTEGER);
		KeyHolder key = new GeneratedKeyHolder();
		getNamedParameterJdbcTemplate().update(INSERT_CONTENT, params, key);
		int id = key.getKey().intValue();

		params = new MapSqlParameterSource();
		params.addValue(SIZE, cis.getCount(), Types.INTEGER);
		getNamedParameterJdbcTemplate().update(UPDATE_CONTENT_SIZE, params);
		return id;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.httpclient.dao.MessageDAO#saveRequest(org.owasp.httpclient.
	 * Request)
	 */
	public void saveRequest(Request request) throws DataAccessException {
		int contentId = -1;
		if (request.getContent() != null)
			contentId = saveMessageContent(request.getContent());
		saveRequestHeader(request, contentId);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.httpclient.dao.MessageDAO#saveRequestHeader(org.owasp.httpclient
	 * .RequestHeader, int)
	 */
	public void saveRequestHeader(RequestHeader requestHeader, int contentId)
			throws DataAccessException {
		saveMessageHeader(requestHeader, contentId);
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(ID, requestHeader.getId(), Types.INTEGER);
		params.addValue(HOST, requestHeader.getHost(), Types.VARCHAR);
		params.addValue(PORT, requestHeader.getPort(), Types.INTEGER);
		params.addValue(SSL, requestHeader.isSsl(), Types.BIT);
		getNamedParameterJdbcTemplate().update(INSERT_REQUEST, params);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.httpclient.dao.MessageDAO#saveResponse(org.owasp.httpclient
	 * .Response)
	 */
	public void saveResponse(Response response) throws DataAccessException {
		int contentId = -1;
		if (response.getContent() != null)
			contentId = saveMessageContent(response.getContent());
		saveResponseHeader(response, contentId);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.httpclient.dao.MessageDAO#saveResponseHeader(org.owasp.httpclient
	 * .ResponseHeader, int)
	 */
	public void saveResponseHeader(ResponseHeader responseHeader, int contentId)
			throws DataAccessException {
		saveMessageHeader(responseHeader, contentId);
	}

	private void saveMessageHeader(MessageHeader header, int contentId) {
		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue(HEADER, header.getHeader(), Types.LONGVARBINARY);
		params.addValue(CONTENTID, contentId != -1 ? contentId : null,
				Types.INTEGER);
		KeyHolder key = new GeneratedKeyHolder();
		getNamedParameterJdbcTemplate().update(INSERT_HEADER, params, key);
		header.setId(key.getKey().intValue());
	}

	private static class RequestMapper implements
			ParameterizedRowMapper<Request> {

		public Request mapRow(ResultSet rs, int rowNum) throws SQLException {
			int id = rs.getInt(ID);

			String host = rs.getString(HOST);
			int port = rs.getInt(PORT);
			boolean ssl = rs.getBoolean(SSL);

			Request request = new Request.Impl();
			request.setId(id);
			request.setHost(host);
			request.setPort(port);
			request.setSsl(ssl);
			request.setHeader(rs.getBytes(HEADER));
			return request;
		}

	}

	private static class ResponseMapper implements
			ParameterizedRowMapper<Response> {

		public Response mapRow(ResultSet rs, int rowNum) throws SQLException {
			int id = rs.getInt(ID);

			Response response = new Response.Impl();
			response.setId(id);
			response.setHeader(rs.getBytes(HEADER));
			return response;
		}

	}

	private static class ContentMapper implements
			ParameterizedRowMapper<byte[]> {

		public byte[] mapRow(ResultSet rs, int rowNum) throws SQLException {
			return rs.getBytes(CONTENT);
		}
	}

	private static class IdMapper implements ParameterizedRowMapper<Integer> {

		public Integer mapRow(ResultSet rs, int rowNum) throws SQLException {
			return Integer.valueOf(rs.getInt(ID));
		}
	}

	private static class ConversationMapper implements
			ParameterizedRowMapper<Conversation> {

		public Conversation mapRow(ResultSet rs, int rowNum)
				throws SQLException {
			Conversation c = new Conversation();
			c.setId(rs.getInt(ID));
			c.setRequestId(rs.getInt(REQUESTID));
			c.setResponseId(rs.getInt(RESPONSEID));

			Timestamp t;
			long requestTime = 0, responseHeaderTime = 0, responseContentTime = 0;
			if ((t = rs.getTimestamp(REQUEST_TIME)) != null)
				requestTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_HEADER_TIME)) != null)
				responseHeaderTime = t.getTime();
			if ((t = rs.getTimestamp(RESPONSE_CONTENT_TIME)) != null)
				responseContentTime = t.getTime();
			c.setRequestTime(requestTime);
			c.setResponseHeaderTime(responseHeaderTime);
			c.setResponseContentTime(responseContentTime);

			return c;
		}
	}
}
