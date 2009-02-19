package org.owasp.httpclient;

public class Conversation {

	private int id, requestId, responseId;

	private long requestTime, responseHeaderTime, responseContentTime;

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

	/**
	 * @return the requestTime
	 */
	public long getRequestTime() {
		return requestTime;
	}

	/**
	 * @param requestTime
	 *            the requestTime to set
	 */
	public void setRequestTime(long requestTime) {
		this.requestTime = requestTime;
	}

	/**
	 * @return the responseHeaderTime
	 */
	public long getResponseHeaderTime() {
		return responseHeaderTime;
	}

	/**
	 * @param responseHeaderTime
	 *            the responseHeaderTime to set
	 */
	public void setResponseHeaderTime(long responseHeaderTime) {
		this.responseHeaderTime = responseHeaderTime;
	}

	/**
	 * @return the responseContentTime
	 */
	public long getResponseContentTime() {
		return responseContentTime;
	}

	/**
	 * @param responseContentTime
	 *            the responseContentTime to set
	 */
	public void setResponseContentTime(long responseContentTime) {
		this.responseContentTime = responseContentTime;
	}

}
