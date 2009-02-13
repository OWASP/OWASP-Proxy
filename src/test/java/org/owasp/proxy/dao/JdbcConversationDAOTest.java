package org.owasp.proxy.dao;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.ConversationSummary;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.jdbc.support.rowset.SqlRowSetMetaData;

public class JdbcConversationDAOTest {

	private static DriverManagerDataSource dataSource = null;
	private static JdbcConversationDAO dao = null;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName("org.h2.Driver");
		dataSource.setUrl("jdbc:h2:mem:webscarab3;DB_CLOSE_DELAY=-1");
		dataSource.setUsername("sa");
		dataSource.setPassword("");
		dao = new JdbcConversationDAO();
		dao.setDataSource(dataSource);
	}

	@Before
	public void setUp() {
		try {
			dao.getJdbcTemplate().execute("DROP SEQUENCE ids");
			dao.getJdbcTemplate().execute("DROP TABLE MESSAGES");
			dao.getJdbcTemplate().execute("DROP TABLE REQUESTS");
			dao.getJdbcTemplate().execute("DROP TABLE CONVERSATIONS");
		} catch (DataAccessException e) {
			// e.printStackTrace();
		}
		dao.createTables();
	}

	@After
	public void tearDown() {
		dump(dao.getJdbcTemplate().queryForRowSet("SELECT * FROM messages"));
		dump(dao.getJdbcTemplate().queryForRowSet("SELECT * FROM requests"));
		dump(dao.getJdbcTemplate()
				.queryForRowSet("SELECT * FROM conversations"));
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		dao.getJdbcTemplate().execute("SHUTDOWN");
	}

	@Test
	public void testAddConversation() throws MessageFormatException {
		Conversation c = dao.findConversation(0);
		assertNull(c);

		c = constructConversation();

		dao.saveConversation(c);

		int cid = c.getId();

		ConversationSummary cs = dao.findConversationSummary(cid);
		compare(cs, c);

		Conversation c2 = dao.findConversation(cid);
		compare(cs, c2);

		compare(c.getRequest(), c2.getRequest());
		compare(c.getResponse(), c2.getResponse());

		if (dao.deleteConversation(cid)) {
			assertEquals(null, dao.findConversation(cid));
			assertEquals(null, dao.findConversationSummary(cid));
			assertEquals(null, dao.findRequest(c.getRequest().getId()));
			assertEquals(null, dao.findResponse(c.getResponse().getId()));
		} else {
			fail("Failed to delete the conversation");
		}
	}

	@Test
	public void testGetConversations() {
		int[] ids = new int[3];
		Conversation c = constructConversation();
		dao.saveConversation(c);
		ids[0] = c.getId();
		c = constructConversation();
		dao.saveConversation(c);
		ids[1] = c.getId();
		c = constructConversation();
		dao.saveConversation(c);
		ids[2] = c.getId();
		assertTrue(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
	}

	@Test
	public void testSaveRequest() {
		Request r = constructRequest();
		dao.saveRequest(r);

		Request r2 = dao.findRequest(r.getId());
		compare(r, r2);

		System.out.println(r2);
	}

	@Test
	public void testSaveResponse() {
		Response r = constructResponse();
		dao.saveResponse(r);

		Response r2 = dao.findResponse(r.getId());
		compare(r, r2);

		System.out.println(r2);
	}

	public static void dump(SqlRowSet rs) {
		try {
			SqlRowSetMetaData rsmd = rs.getMetaData();
			int c = rsmd.getColumnCount();
			for (int i = 1; i <= c; i++) {
				System.out.print(rsmd.getColumnLabel(i));
				System.out.print(i == c ? "\n" : "\t");
			}
			while (rs.next()) {
				for (int i = 1; i <= c; i++) {
					System.out.print(rs.getObject(i));
					System.out.print(i == c ? "\n" : "\t");
				}
			}
			System.out.println("================\n\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private Conversation constructConversation() {
		Conversation c = new Conversation();
		c.setRequestTime(System.currentTimeMillis());
		c.setResponseHeaderTime(System.currentTimeMillis() + 7);
		c.setResponseContentTime(System.currentTimeMillis() + 14);
		c.setRequest(constructRequest());
		c.setResponse(constructResponse());
		c.setConnection("connection-");
		return c;
	}

	private Request constructRequest() {
		Request r = new Request();
		r.setMessage("GET / HTTP/1.0\r\n\r\n".getBytes());
		r.setHost("localhost");
		r.setPort(80);
		r.setSsl(false);
		return r;
	}

	private Response constructResponse() {
		Response r = new Response();
		r.setMessage(("HTTP/1.0 200 Ok blah\r\n"
				+ "Content-Type: text\r\n\r\ncontent").getBytes());
		return r;
	}

	private void compare(ConversationSummary cs, Conversation c)
			throws MessageFormatException {
		assertTrue(cs.getId() == c.getId());
		assertTrue(cs.getRequestTime() == c.getRequestTime());
		assertTrue(cs.getResponseHeaderTime() == c.getResponseHeaderTime());
		assertTrue(cs.getResponseContentTime() == c.getResponseContentTime());
		assertEquals(cs.getConnection(), c.getConnection());
		compare(cs, c.getRequest());
		compare(cs, c.getResponse());
	}

	private void compare(ConversationSummary cs, Request request)
			throws MessageFormatException {
		assertEquals(cs.getHost(), request.getHost());
		assertTrue(cs.getPort() == request.getPort());
		assertTrue(cs.isSsl() == request.isSsl());
		assertEquals(cs.getRequestMethod(), request.getMethod());
		assertEquals(cs.getRequestResource(), request.getResource());
		assertEquals(cs.getRequestContentType(), request
				.getHeader("Content-Type"));
		assertTrue(cs.getRequestContentSize() == 0 ? request.getContent() == null
				|| request.getContent().length == 0
				: cs.getRequestContentSize() == request.getContent().length);
	}

	private void compare(ConversationSummary cs, Response response)
			throws MessageFormatException {
		assertEquals(cs.getResponseStatus(), response.getStatus());
		assertEquals(cs.getResponseReason(), response.getReason());
		assertEquals(cs.getResponseContentType(), response
				.getHeader("Content-Type"));
		assertTrue(cs.getResponseContentSize() == 0 ? response.getContent() == null
				|| response.getContent().length == 0
				: cs.getResponseContentSize() == response.getContent().length);
	}

	private void compare(Request r1, Request r2) {
		assertTrue(Arrays.equals(r1.getHeader(), r2.getHeader()));
		assertTrue(Arrays.equals(r1.getContent(), r2.getContent()));
		assertEquals(r1.getHost(), r2.getHost());
		assertEquals(r1.getPort(), r2.getPort());
		assertEquals(r1.isSsl(), r2.isSsl());
		assertEquals(r1.getId(), r2.getId());
	}

	private void compare(Response r1, Response r2) {
		assertTrue(Arrays.equals(r1.getHeader(), r2.getHeader()));
		assertTrue(Arrays.equals(r1.getContent(), r2.getContent()));
		assertEquals(r1.getId(), r2.getId());
	}

}
