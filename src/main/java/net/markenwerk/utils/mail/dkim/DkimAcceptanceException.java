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

	public DkimAcceptanceException(String message) {
		super(message);
	}

	public DkimAcceptanceException(String message, Exception e) {
		super(message, e);
	}

}
