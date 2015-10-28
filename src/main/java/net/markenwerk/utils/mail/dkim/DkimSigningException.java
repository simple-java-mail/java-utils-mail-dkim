/*
 * Copyright (c) 2015 Torsten Krause, Markenwerk GmbH.
 * 
 * This file is part of 'A DKIM library for JavaMail', hereafter
 * called 'this library', identified by the following coordinates:
 * 
 *    groupID: net.markenwerk
 *    artifactId: utils-mail-dkim
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * 
 * See the LICENSE and NOTICE files in the root directory for further
 * information.
 */
package net.markenwerk.utils.mail.dkim;

import java.io.IOException;

import javax.mail.MessagingException;

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
