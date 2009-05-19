/**
 * 
 */
package org.owasp.httpclient.io;

public class SizeLimitExceededException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public SizeLimitExceededException(String message) {
		super(message);
	}
}