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

public class JSignInternalProperties {

	private static final long JSIGN_TIMEOUT_DEFAULT = TimeUnit.MINUTES.toSeconds(2);
	private static final String JSIGN_URL = "windows.jsign.url";
	private static final String JSIGN_DESCRIPTION = "windows.jsign.description";
	private static final String JSIGN_TIMEOUT = "windows.jsign.timeout";
	private static final String JSIGN_REPLACE = "windows.jsign.replace";
	private static final String JSIGN_TS_AUTHORITY = "windows.jsign.tsa";
	private static final String JSIGN_TS_MODE = "windows.jsign.timestamping.mode";
	private static final String JSIGN_TS_RETRIES = "windows.jsign.timestamping.retries";
	private static final String JSIGN_TS_RETRY_WAIT = "windows.jsign.timestamping.retry_wait";

	private static final String JSIGN_KEYSTORE_PASSWORD = "windows.jsign.keystore.password";
	private static final String JSIGN_KEYSTORE_ALIAS = "windows.jsign.keystore.alias";
	private static final String JSIGN_KEYSTORE_TYPE = "windows.jsign.keystore.type";
	private static final String JSIGN_KEYSTORE = "windows.jsign.keystore";
	private static final String JSIGN_CERTCHAIN = "windows.jsign.certchain";
	private static final String JSIGN_SIGALG = "windows.jsign.sigalg";
	private static final String JSIGN_DIGESTALG = "windows.jsign.digestalg";
	private static final String JSIGN_PROVIDER = "windows.jsign.provider";
	private static final String JSIGN_PROVIDER_ARG = "windows.jsign.provider.arg";

	private static final String JSIGN_HTTP_PROXY_HOST = "windows.jsign.http.proxy.host";
	private static final String JSIGN_HTTPS_PROXY_HOST = "windows.jsign.https.proxy.host";

	private static final String JSIGN_HTTP_PROXY_PORT = "windows.jsign.http.proxy.port";
	private static final String JSIGN_HTTPS_PROXY_PORT = "windows.jsign.https.proxy.port";

	private final PropertiesReader propertiesReader;

	/**
	 * Default constructor.
	 *
	 * @param propertiesReader the properties reader that will be used to read
	 *                         configuration value.
	 */
	public JSignInternalProperties(PropertiesReader propertiesReader) {
		this.propertiesReader = propertiesReader;
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

	public int getTimeStampingRetries() {
		return propertiesReader.getInt(JSIGN_TS_RETRIES, 3);
	}

	public int getTimeStampingRetryWait() {
		return propertiesReader.getInt(JSIGN_TS_RETRY_WAIT, 5);
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

	public String getHttpsProxyHost() {
		return propertiesReader.getString(JSIGN_HTTPS_PROXY_HOST, "");
	}

	public int getHttpProxyPort() {
		return propertiesReader.getInt(JSIGN_HTTP_PROXY_PORT, 0);
	}

	public int getHttpsProxyPort() {
		return propertiesReader.getInt(JSIGN_HTTPS_PROXY_PORT, 0);
	}

	public String getSigalg() {
		return propertiesReader.getString(JSIGN_SIGALG, "");
	}

	public String getDigestalg() {
		return propertiesReader.getString(JSIGN_DIGESTALG, "SHA-256");
	}

	public String getKeystoreType() {
		return propertiesReader.getString(JSIGN_KEYSTORE_TYPE, "");
	}

	public String getProvider() {
		return propertiesReader.getString(JSIGN_PROVIDER, "");
	}

	public String getProviderArg() {
		return propertiesReader.getString(JSIGN_PROVIDER_ARG, "");
	}

	public Path getCertchain() {
		return propertiesReader.getPath(JSIGN_CERTCHAIN, "");
	}

}
