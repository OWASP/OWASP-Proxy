package org.owasp.webscarab.model;

public class MessageFormatException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2215306096234406521L;

	public MessageFormatException(String message) {
		super(message);
	}
	
	public MessageFormatException(Throwable cause) {
		super(cause);
	}
	
	public MessageFormatException(String message, Throwable cause) {
		super(message, cause);
	}
	
}
