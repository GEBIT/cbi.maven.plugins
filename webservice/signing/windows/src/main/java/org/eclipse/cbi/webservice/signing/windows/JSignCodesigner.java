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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.eclipse.cbi.common.util.Paths;
import org.eclipse.cbi.util.ProcessExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

@AutoValue
public abstract class JSignCodesigner implements Codesigner {

	private static Logger logger = LoggerFactory.getLogger(JSignCodesigner.class);;

	@Override
	public void sign(Path file, String name, URI url) throws IOException {
		Path out = null;
		try {
			StringBuffer output = new StringBuffer();
			int jsignExitValue = processExecutor().exec(createCommand(file, name, url), output, timeout(), TimeUnit.SECONDS);
			if (jsignExitValue != 0) {
				throw new IOException(Joiner.on('\n').join(
						"The '" + jsignjar().toString() + "' command exited with value '" + jsignExitValue + "'",
						"'" + jsignjar().toString() + "' output:",
						output));
			}
		} finally {
			if (out != null && Files.exists(out)) {
				try {
					Paths.delete(out);
				} catch (IOException e) {
					logger.error("Error occured while deleting temporary resource '"+out.toString()+"'", e);
				}
			}
		}
	}

	private ImmutableList<String> createCommand(Path file, String name, URI url) {
		ImmutableList.Builder<String> builder = ImmutableList.<String>builder();
		builder.add("java")
				.add("-jar")
				.add(jsignjar().toString());


		if (!Strings.isNullOrEmpty(keystore().toString())) {
			builder.add("--keystore").add(keystore().toString());
			builder.add("--alias").add(keystoreAlias());
			if (!Strings.isNullOrEmpty(keystorePassword().toString())) {
				builder.add("--storepass").add(keystorePassword());
			}
			if (!Strings.isNullOrEmpty(keystoreType().toString())) {
				builder.add("--storetype").add(keystoreType());
			}
		}
		if (!Strings.isNullOrEmpty(keyfile().toString())) {
			builder.add("--keyfile").add(keyfile().toString());
			if (!Strings.isNullOrEmpty(keyfilePassword().toString())) {
				builder.add("--keypass").add(keyfilePassword());
			}
		}
		if (!Strings.isNullOrEmpty(certfile().toString())) {
			builder.add("--certfile").add(certfile().toString());
		}
		if (!Strings.isNullOrEmpty(digestalg())) {
			builder.add("--alg").add(digestalg());
		}
		if (!Strings.isNullOrEmpty(httpProxyHost())) {
			String proxyUrl = "http://" + httpProxyHost();
			if (httpProxyPort() != 0) {
				proxyUrl += ":" + httpProxyPort();
			}
			builder.add("--proxyUrl").add(proxyUrl);
		}
		if (replace()) {
			builder.add("--replace");
		}
		if (name != null || description().isPresent()) {
			builder.add("--name").add(name != null ? name : description().get());
		}
		if (url != null || url().isPresent()) {
			builder.add("--url").add(url != null ? url.toString() : url().get().toString());
		}

		return builder.add(file.toString()).build();
	}

	public static Builder builder() {
		return new AutoValue_JSignCodesigner.Builder();
	}

	/**
	 * Path to the JSign jar.
	 * @return
	 */
	abstract Path jsignjar();

	abstract Optional<String> description();

	abstract Optional<URI> url();


	/**
	 * Returns the keystore file, or the SunPKCS11 configuration file
	 *
	 * @return the keystore file, or the SunPKCS11 configuration file
	 */
	abstract Path keystore();

	/**
	 * Returns the path to the file storing the keystore password
	 *
	 * @return the path to the file storing the keystore password
	 */
	abstract String keystorePassword();


	/**
	 * Returns the type of the keystore:
	 * <ul>
	 * <li>JKS: Java keystore (.jks files)</li>
	 * <li>PKCS12: Standard PKCS#12 keystore (.p12 or .pfx files)</li>
	 * <li>PKCS11: PKCS#11 hardware token</li>
	 *
	 * @return the type of the keystore
	 */
	abstract String keystoreType();

	/**
	 * Returns the alias of the certificate used for signing in the keystore
	 *
	 * @return the alias of the certificate used for signing in the keystore //
	 //         -a,--alias <NAME>
	 */
	abstract String keystoreAlias();

	/**
	 * Returns the path to the file storing the password of the private key. When
	 * using a keystore, this parameter can be omitted if the keystore shares the
	 * same password.
	 *
	 * @return the path to the file storing the password of the private key. When
	 *         using a keystore, this parameter can be omitted if the keystore
	 *         shares the same password.
	 */
	abstract String keyfilePassword();

	/**
	 * Returns the file containing the private key. PEM and PVK files are
	 * supported.
	 *
	 * @return the file containing the private key. PEM and PVK files are
	 *         supported.
	 */
	abstract Path keyfile();

	/**
	 * Returns the file containing the PKCS#7 certificate chain (.p7b or .spc
	 * files).
	 *
	 * @return the file containing the PKCS#7 certificate chain (.p7b or .spc
	 *         files).
	 */
	abstract Path certfile();

	/**
	 * Returns the digest algorithm (SHA-1, SHA-256, SHA-384 or SHA-512)
	 *
	 * @return the digest algorithm (SHA-1, SHA-256, SHA-384 or SHA-512)
	 */
	abstract String digestalg();

	/**
	 * Returns the timestamping authority URI
	 *
	 * @return the timestamping authority URI
	 */
	abstract String timestampingAuthority();

	/**
	 * Returns the timestamping mode (RFC3161 or Authenticode)
	 *
	 * @return the timestamping mode (RFC3161 or Authenticode)
	 */
	abstract String timestampingMode();

	abstract String httpProxyHost();

	abstract int httpProxyPort();

	/**
	 * Tells if previous signatures should be replaced.
	 *
	 * @return true if previous signatures should be replaced.
	 */
	abstract boolean replace();

	abstract long timeout();

	abstract ProcessExecutor processExecutor();

	@AutoValue.Builder
	public static abstract class Builder {
		public abstract JSignCodesigner build();

		public abstract Builder jsignjar(Path jsignjar);

		public abstract Builder replace(boolean replace);

		public abstract Builder description(Optional<String> description);

		public abstract Builder url(Optional<URI> uri);

		/**
		 * Sets the path to the keystore file.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder keystore(Path keystore);

		/**
		 * Sets the path to the file storing the password of the keystore.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder keystorePassword(String keystorePassword);

		/**
		 * Sets the alias name of the key in the keystore.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder keystoreAlias(String keystoreAlias);

		/**
		 * Sets the URI of the timestamping authority used by jarsigner.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder timestampingAuthority(String timeStampingAuthority);

		public abstract Builder timestampingMode(String timeStampingMode);

		/**
		 * Sets the timeout before which the jarsigner process will be killed.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder timeout(long timeout);

		public abstract Builder httpProxyHost(String proxyHost);

		public abstract Builder httpProxyPort(int proxyPort);

		public abstract Builder digestalg(String digestalg);

		public abstract Builder keystoreType(String keystoreType);

		public abstract Builder certfile(Path certfile);

		public abstract Builder keyfile(Path keyfile);

		public abstract Builder keyfilePassword(String keypass);

		public abstract Builder processExecutor(ProcessExecutor processExecutor);
	}
}
