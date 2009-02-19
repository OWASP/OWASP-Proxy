package org.owasp.httpclient.dao;

import java.io.InputStream;
import java.util.Collection;

import org.owasp.httpclient.Conversation;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.springframework.dao.DataAccessException;

public interface MessageDAO {

	void saveRequest(Request request) throws DataAccessException;

	void saveRequestHeader(RequestHeader requestHeader, int contentId)
			throws DataAccessException;

	void saveResponse(Response response) throws DataAccessException;

	void saveResponseHeader(ResponseHeader responseHeader, int contentId)
			throws DataAccessException;

	int saveMessageContent(InputStream messageContent)
			throws DataAccessException;

	int saveMessageContent(byte[] messageContent) throws DataAccessException;

	Request loadRequest(int id) throws DataAccessException;

	RequestHeader loadRequestHeader(int id) throws DataAccessException;

	Response loadResponse(int id) throws DataAccessException;

	ResponseHeader loadResponseHeader(int id) throws DataAccessException;

	byte[] loadMessageContent(int id) throws DataAccessException;

	int getMessageContentSize(int id) throws DataAccessException;

	int getMessageContentId(int headerId) throws DataAccessException;

	int saveConversation(int requestId, int responseId, long requestTime,
			long responseHeaderTime, long responseContentTime)
			throws DataAccessException;

	Conversation getConversation(int id) throws DataAccessException;

	Collection<Integer> listConversations() throws DataAccessException;

	Collection<Integer> listConversationsSince(int conversationId)
			throws DataAccessException;

	boolean deleteConversation(int id) throws DataAccessException;

}
