package org.simplejavamail.utils.mail.dkim;

/**
 * A {@link RuntimeException} that is used to indicate DKIM specific
 * missbehaviors or to wrap other {@link Exception Exceptions} that were thrown
 * during the processing of DKIM specific operations.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class DkimException extends RuntimeException {

	private static final long serialVersionUID = -3899148862673205389L;

	/**
	 * Constructs a {@code DkimException} with the given message.
	 *
	 * @param message
	 *            The message.
	 */
	public DkimException(String message) {
		super(message);
	}

	/**
	 * Constructs a {@code DkimException} with the given message and cause. The
	 * given cause is chained to this exception.
	 *
	 * @param message
	 *            The message.
	 * @param cause
	 *            The causing exception.
	 */
	public DkimException(String message, Exception cause) {
		super(message, cause);
	}

}
