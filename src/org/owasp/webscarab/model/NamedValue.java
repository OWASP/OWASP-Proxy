package org.owasp.webscarab.model;

public class NamedValue {

	private String name;
	
	private String separator;
	
	private String value;
	
	public NamedValue(String name, String separator, String value) {
		this.name = name;
		this.separator = separator;
		this.value = value;
	}
	
	public String getName() {
		return name;
	}
	
	public String getSeparator() {
		return separator;
	}
	
	public String getValue() {
		return this.value;
	}
	
	@Override
	public String toString() {
		return name + separator + value;
	}
	
	/**
	 * parses a string into a NamedValue
	 * 
	 * @param string the string to parse
	 * @param separator a regular expression specifying the separator between the name and the value
	 * @return a NamedValue containing the parsed name, separator, and value
	 * @throws MessageFormatException if the separator couldn't be found, or if the name and value could not be parsed
	 */
	public static NamedValue parse(String string, String separator) throws MessageFormatException {
		String[] parts = string.split(separator, 2);
		if (parts.length != 2)
			throw new MessageFormatException("Couldn't parse invalid named value: '" + string + "'");
		String sep = string.substring(parts[0].length(), string.length() - parts[1].length());
		return new NamedValue(parts[0], sep, parts[1]);
	}
	
	public static NamedValue[] parse(String string, String delimiter, String separator) throws MessageFormatException {
		String[] nvs = string.split(delimiter);
		NamedValue[] values = new NamedValue[nvs.length];
		for (int i= 0; i < values.length; i++)
			values[i] = parse(nvs[i], separator);
		return values;
	}
	
	/**
	 * Joins multiple NamedValues into a single String
	 * 
	 * @param values the values to join 
	 * @param separator the separator between the values
	 * @return a string containing the joined values
	 */
	public static String join(NamedValue[] values, String separator) {
		StringBuilder buff = new StringBuilder();
		for (int i=0; i<values.length; i++) {
			buff.append(values[i]);
			if (i<values.length - 1)
				buff.append(separator);
		}
		return buff.toString();
	}
	
}
