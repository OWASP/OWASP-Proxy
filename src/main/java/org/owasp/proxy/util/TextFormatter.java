package org.owasp.proxy.util;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * 
 * @author rogan
 */
public class TextFormatter extends Formatter {

	SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss ");

	/** Creates a new instance of TextFormatter */
	public TextFormatter() {
	}

	public String format(LogRecord record) {
		StringBuffer buff = new StringBuffer(100);
		buff.append(sdf.format(new Date(record.getMillis())));
		buff.append(Thread.currentThread().getName());
		String className = record.getSourceClassName();
		if (className.indexOf(".") > -1) {
			className = className.substring(className.lastIndexOf(".") + 1,
					className.length());
		}
		buff.append("(").append(className).append(".");
		buff.append(record.getSourceMethodName()).append("): ");
		buff.append(record.getMessage());
		if (record.getParameters() != null) {
			Object[] params = record.getParameters();
			buff.append(" { ").append(params[0]);
			for (int i = 1; i < params.length; i++) {
				buff.append(", ").append(params[i]);
			}
			buff.append(" }");
		}
		buff.append("\n");
		return buff.toString();
	}

}
