/*******************************************************************************
 * Copyright (c) 2015 Eclipse Foundation and others
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Mikaël Barbero - initial implementation
 *******************************************************************************/
package org.eclipse.cbi.webservice.signing.windows;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.eclipse.cbi.util.PropertiesReader;

import com.google.common.base.Strings;

import net.jsign.timestamp.TimestampingMode;

public class JSignProperties {

	private static final long JSIGN_TIMEOUT_DEFAULT = TimeUnit.MINUTES.toSeconds(2);
	private static final String JSIGN_URL = "windows.jsign.url";
	private static final String JSIGN_DESCRIPTION = "windows.jsign.description";
	private static final String JSIGN_TIMEOUT = "windows.jsign.timeout";
	private static final String JSIGN_REPLACE = "windows.jsign.replace";
	private static final String JSIGN_TS_AUTHORITY = "windows.jsign.tsa";
	private static final String JSIGN_TS_MODE = "windows.jsign.timestamping.mode";

	private static final String JSIGN_KEYSTORE_PASSWORD = "windows.jsign.keystore.password";
	private static final String JSIGN_KEYSTORE_ALIAS = "windows.jsign.keystore.alias";
	private static final String JSIGN_KEYSTORE_TYPE = "windows.jsign.keystore.type";
	private static final String JSIGN_KEYSTORE = "windows.jsign.keystore";
	private static final String JSIGN_CERTFILE = "windows.jsign.certfile";
	private static final String JSIGN_DIGESTALG = "windows.jsign.digestalg";
	private static final String JSIGN_KEYFILE = "windows.jsign.keyfile";
	private static final String JSIGN_KEYFILE_PASSWORD = "windows.jsign.keyfile.password";

	private static final String JSIGN_HTTP_PROXY_HOST = "windows.jsign.http.proxy.host";

	private static final String JSIGN_HTTP_PROXY_PORT = "windows.jsign.http.proxy.port";

	private static final String JSIGN_JAR = "windows.jsign.jar";

	private final PropertiesReader propertiesReader;

	/**
	 * Default constructor.
	 *
	 * @param propertiesReader the properties reader that will be used to read
	 *                         configuration value.
	 */
	public JSignProperties(PropertiesReader propertiesReader) {
		this.propertiesReader = propertiesReader;
	}

	public Path getJsignjar() {
		return propertiesReader.getPath(JSIGN_JAR);
	}

	public Optional<URI> getURL() {
		String url = propertiesReader.getString(JSIGN_URL, "");
		if (Strings.isNullOrEmpty(url)) {
			return Optional.empty();
		}
		try {
			return Optional.of(new URI(url));
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Property '" + JSIGN_URL + "' must be a valid URI (currently '" + url + "')", e);
		}
	}

	public Optional<String> getDescription() {
		String name = propertiesReader.getString(JSIGN_DESCRIPTION, "");
		if (Strings.isNullOrEmpty(name)) {
			return Optional.empty();
		}
		return Optional.of(name);
	}

	/**
	 * Reads and returns the path to the keystore file.
	 *
	 * @return the path to the keystore file.
	 */
	public Path getKeystore() {
		if ("NONE".equals(propertiesReader.getString(JSIGN_KEYSTORE))) {
			// is acceptable here
			return propertiesReader.getPath(JSIGN_KEYSTORE);
		}
		return propertiesReader.getRegularFile(JSIGN_KEYSTORE);
	}

	/**
	 * Reads and returns the name of the alias of the key to be used in the
	 * keystore.
	 *
	 * @return the name of the alias of the key to be used in the keystore.
	 */
	public boolean getReplace() {
		return propertiesReader.getBoolean(JSIGN_REPLACE, false);
	}

	/**
	 * Reads and returns the name of the alias of the key to be used in the
	 * keystore.
	 *
	 * @return the name of the alias of the key to be used in the keystore.
	 */
	public String getKeystoreAlias() {
		return propertiesReader.getString(JSIGN_KEYSTORE_ALIAS);
	}

	/**
	 * Reads and returns the path to the file containing the password of the
	 * keystore.
	 *
	 * @return the path to the file containing the password of the keystore.
	 */
	public String getKeystorePassword() {
		return propertiesReader.getFileContent(JSIGN_KEYSTORE_PASSWORD);
	}

	/**
	 * Reads and returns the URI of the timestamping authority to be used by the
	 * jsign command
	 *
	 * @return the URI of the timestamping authority to be used by the jsign command
	 */
	public String getTimeStampingAuthority() {
		return propertiesReader.getString(JSIGN_TS_AUTHORITY);
	}

	public String getTimeStampingMode() {
		return propertiesReader.getString(JSIGN_TS_MODE, TimestampingMode.AUTHENTICODE.name());
	}

	/**
	 * Reads and returns the timeout of the jsign command. If no
	 * {@value #JSIGN_TIMEOUT} property can be found returns the default value '120'
	 * seconds.
	 */
	public long getTimeout() {
		return propertiesReader.getLong(JSIGN_TIMEOUT, JSIGN_TIMEOUT_DEFAULT);
	}

	public String getHttpProxyHost() {
		return propertiesReader.getString(JSIGN_HTTP_PROXY_HOST, "");
	}

	public int getHttpProxyPort() {
		return propertiesReader.getInt(JSIGN_HTTP_PROXY_PORT, 0);
	}

	public String getDigestalg() {
		return propertiesReader.getString(JSIGN_DIGESTALG, "SHA-256");
	}

	public String getKeystoreType() {
		return propertiesReader.getString(JSIGN_KEYSTORE_TYPE, "");
	}

	public Path getCertfile() {
		return propertiesReader.getPath(JSIGN_CERTFILE, "");
	}

	public Path getKeyfile() {
		return propertiesReader.getPath(JSIGN_KEYFILE, "");
	}

	/**
	 * Reads and returns the path to the file containing the password of the
	 * keyfile.
	 *
	 * @return the path to the file containing the password of the keyfile.
	 */
	public String getKeyfilePassword() {
		if (Strings.isNullOrEmpty(propertiesReader.getString(JSIGN_KEYFILE_PASSWORD, ""))) {
			return "";
		}
		return propertiesReader.getFileContent(JSIGN_KEYFILE_PASSWORD);
	}
}
