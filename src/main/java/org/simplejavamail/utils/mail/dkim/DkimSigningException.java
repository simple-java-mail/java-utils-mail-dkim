package org.simplejavamail.utils.mail.dkim;

import java.io.IOException;

import jakarta.mail.MessagingException;

/**
 * A {@link MessagingException} that is used to indicate DKIM specific
 * missbehaviors or to wrap other {@link Exception Exceptions} that were thrown
 * during the processing of a DKIM signature, or operations necessary for DKIM
 * signatures.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class DkimSigningException extends MessagingException {

	private static final long serialVersionUID = -3899148862673205389L;

	/**
	 * Constructs a {@code DkimSigningException} with the given message.
	 *
	 * @param message
	 *            The message.
	 */
	public DkimSigningException(String message) {
		/*
		 * This is a hack: If an {@link Exception} caught in {@link IOException}
		 * or a {@link MessagingException} caused by an {@link IOException},
		 * {@link SMTPTransport} will hang forever (neither returning, nor
		 * throwing the exception)
		 */
		super(message, new IOException());
	}

	/**
	 * Constructs a {@code DkimSigningException} with the given message and
	 * cause. The given cause is chained to this exception.
	 *
	 * @param message
	 *            The message.
	 * @param cause
	 *            The causing exception.
	 */
	public DkimSigningException(String message, Exception cause) {
		/*
		 * This is a hack: If an {@link Exception} caught in {@link IOException}
		 * or a {@link MessagingException} caused by an {@link IOException},
		 * {@link SMTPTransport} will hang forever (neither returning, nor
		 * throwing the exception)
		 */
		super(message, new IOException(cause));
	}

}
