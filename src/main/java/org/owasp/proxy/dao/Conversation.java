package org.owasp.proxy.dao;

public class Conversation {

	private int id, requestId, responseId;

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @param id
	 *            the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * @return the requestId
	 */
	public int getRequestId() {
		return requestId;
	}

	/**
	 * @param requestId
	 *            the requestId to set
	 */
	public void setRequestId(int requestId) {
		this.requestId = requestId;
	}

	/**
	 * @return the responseId
	 */
	public int getResponseId() {
		return responseId;
	}

	/**
	 * @param responseId
	 *            the responseId to set
	 */
	public void setResponseId(int responseId) {
		this.responseId = responseId;
	}

}
