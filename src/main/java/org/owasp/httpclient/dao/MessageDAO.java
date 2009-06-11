package org.owasp.httpclient.dao;

import java.io.InputStream;
import java.util.Collection;

import org.owasp.httpclient.MutableBufferedRequest;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.MutableRequestHeader;
import org.owasp.httpclient.MutableResponseHeader;
import org.springframework.dao.DataAccessException;

public interface MessageDAO {

	void saveRequest(MutableBufferedRequest request) throws DataAccessException;

	void saveRequestHeader(MutableRequestHeader requestHeader, int contentId)
			throws DataAccessException;

	void saveResponse(MutableBufferedResponse response) throws DataAccessException;

	void saveResponseHeader(MutableResponseHeader responseHeader, int contentId)
			throws DataAccessException;

	int saveMessageContent(InputStream messageContent)
			throws DataAccessException;

	int saveMessageContent(byte[] messageContent) throws DataAccessException;

	MutableBufferedRequest loadRequest(int id) throws DataAccessException;

	MutableRequestHeader loadRequestHeader(int id) throws DataAccessException;

	MutableBufferedResponse loadResponse(int id) throws DataAccessException;

	MutableResponseHeader loadResponseHeader(int id) throws DataAccessException;

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

	ConversationSummary getConversationSummary(int id)
			throws DataAccessException;

}
