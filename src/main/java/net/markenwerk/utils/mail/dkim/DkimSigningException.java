/* 
 * Copyright 2008 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package net.markenwerk.utils.mail.dkim;

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
