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

/**
 * A {@link DkimSigningException} that is used to indicate that an attempt to
 * sign a {@link DkimMessage} failed, because the {@link DkimSigner}
 * configuration is incompatible with the values retrieved from the DNS.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class DkimAcceptanceException extends DkimSigningException {

	private static final long serialVersionUID = -3899148862673205389L;

	/**
	 * Constructs a {@code DkimAcceptanceException} with the given message.
	 *
	 * @param message
	 *            The message.
	 */
	public DkimAcceptanceException(String message) {
		super(message);
	}

	/**
	 * Constructs a {@code DkimAcceptanceException} with the given message and
	 * cause. The given cause is chained to this exception.
	 *
	 * @param message
	 *            The message.
	 * @param cause
	 *            The causing exception.
	 */
	public DkimAcceptanceException(String message, Exception cause) {
		super(message, cause);
	}

}
