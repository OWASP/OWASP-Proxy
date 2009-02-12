package org.owasp.proxy.dao;

import java.util.Collection;

import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.ConversationSummary;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;
import org.springframework.dao.DataAccessException;

public interface ConversationDAO {

	void saveConversation(Conversation conversation) throws DataAccessException;

	Conversation findConversation(int id) throws DataAccessException;

	ConversationSummary findConversationSummary(int id)
			throws DataAccessException;

	Collection<Integer> listConversations() throws DataAccessException;

	Collection<Integer> listConversationsAfter(int id)
			throws DataAccessException;

	Request findRequest(int id) throws DataAccessException;

	Response findResponse(int id) throws DataAccessException;

	void saveRequest(Request request) throws DataAccessException;

	void saveResponse(Response response) throws DataAccessException;

	boolean deleteConversation(int id) throws DataAccessException;

}
