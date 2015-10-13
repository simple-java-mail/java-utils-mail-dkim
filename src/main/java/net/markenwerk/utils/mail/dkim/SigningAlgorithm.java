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
 * 
 * This file incorporates work covered by the following copyright and  
 * permission notice:
 *  
 *    Copyright 2008 The Apache Software Foundation or its licensors, as
 *    applicable.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *    A licence was granted to the ASF by Florian Sager on 30 November 2008
 */
package net.markenwerk.utils.mail.dkim;

/**
 * Allowed signing algorithms by RFC 4871 with translation to different Java
 * notations.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public enum SigningAlgorithm {

	SHA256_WITH_RSA("rsa-sha256", "SHA256withRSA", "sha-256"),

	SHA1_WITH_RSA("rsa-sha1", "SHA1withRSA", "sha-1");

	private final String rfc4871Notation;
	private final String javaNotation;
	private final String hashNotation;

	private SigningAlgorithm(String rfc4871Notation, String javaNotation, String hashNotation) {
		this.rfc4871Notation = rfc4871Notation;
		this.javaNotation = javaNotation;
		this.hashNotation = hashNotation;
	}

	public String getRfc4871Notation() {
		return rfc4871Notation;
	}

	public String getJavaNotation() {
		return javaNotation;
	}

	public String getHashNotation() {
		return hashNotation;
	}

}
