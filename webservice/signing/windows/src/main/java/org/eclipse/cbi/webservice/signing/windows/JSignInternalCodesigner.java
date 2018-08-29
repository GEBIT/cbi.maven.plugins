/*******************************************************************************
 * Copyright (c) 2015 Eclipse Foundation and others
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Erwin Tratar - initial implementation
 *******************************************************************************/
package org.eclipse.cbi.webservice.signing.windows;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.auto.value.AutoValue;
import com.google.common.base.Strings;

import net.jsign.DigestAlgorithm;
import net.jsign.PESigner;
import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

/**
 * Codesigning implementation using JSign directly in process.
 */
@AutoValue
public abstract class JSignInternalCodesigner implements Codesigner {

	private static Logger logger = LoggerFactory.getLogger(JSignInternalCodesigner.class);;

	@Override
	public void sign(Path file) throws IOException {
		PESigner signer = createSigner(file);

		PEFile peFile = new PEFile(file.toFile());
		logger.info("Adding Authenticode signature to " + file);
		try {
			signer.sign(peFile);
		} catch (Exception e) {
			throw new IOException("Failed to sign " + file, e);
		} finally {
			try {
				peFile.close();
			} catch (IOException e) {
				logger.warn("Couldn't close " + file, e);
			}
		}
	}

	private PESigner createSigner(Path file) throws IOException {
		PrivateKey privateKey;
		Certificate[] chain;

		/*
		 * if (!Strings.isNullOrEmpty(httpProxyHost())) {
		 * command.add("-J-Dhttp.proxyHost=" +
		 * httpProxyHost()).add("-J-Dhttp.proxyPort=" + httpProxyPort()); }
		 *
		 * if (!Strings.isNullOrEmpty(httpProxyHost())) {
		 * command.add("-J-Dhttps.proxyHost=" +
		 * httpsProxyHost()).add("-J-Dhttps.proxyPort=" + httpsProxyPort()); }
		 *
		 * command.add("-tsaurl", timestampingAuthority().toString()) .add("-keystore",
		 * keystore().toString()) .add("-storepass", keystorePassword());
		 *
		 * if (!Strings.isNullOrEmpty(keystoreType())) { command.add("-storetype",
		 * keystoreType()); } if (!Strings.isNullOrEmpty(keystoreAlias())) {
		 * command.add("-alias", keystoreAlias()); }
		 *
		 * if (!Strings.isNullOrEmpty(provider())) { command.add("-provider",
		 * provider()); } if (!Strings.isNullOrEmpty(providerArg())) {
		 * command.add("-providerArg", providerArg()); } if
		 * (!Strings.isNullOrEmpty(digestalg())) { command.add("-alg", digestalg()); }
		 * if (!Strings.isNullOrEmpty(certchain())) { command.add("-certfile",
		 * certchain()); }
		 *
		 * // .add("-pkcs12", pkcs12().toString()) // .add("-pass", pkcs12Password()) //
		 * .add("-n", description()) // .add("-i", uri().toString()) // .add("-t",
		 * timestampURI().toString()) // .add("-in", in.toString()) // .add("-out",
		 * out.toString()) command.add(file.toString());
		 */

		// some exciting parameter validation...
		if ((keystore() == null || "NONE".equals(keystore().toString())) && keystoreType() == null) {
			// no file -> storetype must be set
			throw new IOException("if keystore is not set keystore.type must be set");
		}

		Provider provider = null;
		if (!Strings.isNullOrEmpty(provider())) {

			ClassLoader cl = ClassLoader.getSystemClassLoader();
			Object obj = null;
            try {
            	Class<?> provClass;
	            if (cl != null) {
	                provClass = cl.loadClass(provider());
	            } else {
	                provClass = Class.forName(provider());
	            }
	            if (Strings.isNullOrEmpty(providerArg())) {
	            	obj = provClass.newInstance();
	            } else {
	            	Constructor<?> c =
	            			provClass.getConstructor(String.class);
	            	obj = c.newInstance(providerArg());
	            }
            } catch (Exception ex) {
            	throw new IOException("Failed to create " + provider(), ex);
            }
            if (!(obj instanceof Provider)) {
                throw new IOException(provider() + " is not a Provider");
            }
            provider = (Provider)obj;
		}

		KeyStore ks = load(keystore() != null ? keystore().toFile() : null,
				keystoreType(),
				keystorePassword(),
				provider);

		if (keystoreAlias() == null) {
			throw new IOException("keystore.alias must be set");
		}

		try {
			chain = ks.getCertificateChain(keystoreAlias());
		} catch (KeyStoreException e) {
			throw new IOException(e.getMessage(), e);
		}
		if (chain == null) {
			throw new IOException(
					"No certificate found under the alias '" + keystoreAlias() + "' in the keystore " + keystore());
		}
		if (certchain() != null) {
			// replace certificate chain with complete chain from file
			try {
				chain = loadCertificateChain(certchain().toFile());
			} catch (CertificateException e) {
				throw new IOException("Failed to load certificate chain from " + certchain(), e);
			}
		}

		char[] password = keystorePassword() != null ? keystorePassword().toCharArray() : null;

		try {
			privateKey = (PrivateKey) ks.getKey(keystoreAlias(), password);
		} catch (Exception e) {
			throw new IOException("Failed to retrieve the private key from the keystore", e);
		}

		if (digestalg() != null && DigestAlgorithm.of(digestalg()) == null) {
			throw new IOException("The digest algorithm " + digestalg() + " is not supported");
		}

		String sigalg = sigalg();
		if (Strings.isNullOrEmpty(sigalg)) {
			String keyAlgorithm = privateKey.getAlgorithm();
			if (keyAlgorithm.equalsIgnoreCase("DSA"))
				sigalg = "SHA1withDSA";
			else if (keyAlgorithm.equalsIgnoreCase("RSA"))
				sigalg = "SHA256withRSA";
			else if (keyAlgorithm.equalsIgnoreCase("EC"))
				sigalg = "SHA256withECDSA";
			else
		        throw new IOException("private key is not a DSA or "
                        + "RSA key");
		}

//		try {
//			initializeProxy(proxyUrl, proxyUser, proxyPass);
//		} catch (Exception e) {
//			throw new Exception("Couldn't initialize proxy ", e);
//		}

		// and now the actual work!
		return new PESigner(chain, privateKey)
//				.withProgramName(description())
//				.withProgramURL(url())
				.withDigestAlgorithm(DigestAlgorithm.of(digestalg()))
				.withSignatureProvider(provider)
				.withSignatureAlgorithm(sigalg)
				.withSignaturesReplaced(replace())
				.withTimestamping(timestampingAuthority() != null)
				.withTimestampingMode(timestampingMode() != null ? TimestampingMode.of(timestampingMode())
						: TimestampingMode.AUTHENTICODE)
				.withTimestampingRetries(timestampingRetries())
				.withTimestampingRetryWait(timestampingRetryWait())
				.withTimestampingAutority(
						timestampingAuthority() != null ? timestampingAuthority().toString().split(",") : null);
	}

	private KeyStore load(File keystore, String storetype, String storepass, Provider provider) throws IOException {
        if (keystore != null && storetype == null) {
            // guess the type of the keystore from the extension of the file
            String filename = keystore.getName().toLowerCase();
            if (filename.endsWith(".p12") || filename.endsWith(".pfx")) {
                storetype = "PKCS12";
            } else {
                storetype = "JKS";
            }
        }

        KeyStore ks;
        try {
            if ("PKCS11".equals(storetype)) {
                ks = KeyStore.getInstance(storetype, provider);
            } else {
                ks = KeyStore.getInstance(storetype);
            }
        } catch (KeyStoreException e) {
            throw new IOException("keystore type '" + storetype + "' is not supported", e);
        }

        if (!"PKCS11".equals(storetype) && (keystore == null || !keystore.exists())) {
            throw new IOException("The keystore " + keystore + " couldn't be found");
        }

        try {
            FileInputStream in = "PKCS11".equals(storetype) ? null : new FileInputStream(keystore);
            try {
                ks.load(in, storepass != null ? storepass.toCharArray() : null);
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        } catch (Exception e) {
            throw new IOException("Unable to load the keystore " + keystore, e);
        }

        return ks;
    }

	/**
	 * Load the certificate chain from the specified PKCS#7 files.
	 */
	@SuppressWarnings("unchecked")
	private Certificate[] loadCertificateChain(File file) throws IOException, CertificateException {
		try (FileInputStream in = new FileInputStream(file)) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			Collection<Certificate> certificates = (Collection<Certificate>) certificateFactory
					.generateCertificates(in);
			return certificates.toArray(new Certificate[certificates.size()]);
		}
	}

	public static Builder builder() {
		return new AutoValue_JSignInternalCodesigner.Builder();
	}

//	abstract String description();
//
//	abstract String url();

	abstract long timeout();

	abstract boolean replace();

	/**
	 * Returns the path to the keystore file
	 *
	 * @return the path to the keystore file
	 */
	abstract Path keystore();

	/**
	 * Returns the path to the file storing the keystore password
	 *
	 * @return the path to the file storing the keystore password
	 */
	abstract String keystorePassword();

	/**
	 * Returns the alias name of the key in the keystore
	 *
	 * @return the alias name of the key in the keystore
	 */
	abstract String keystoreAlias();

	/**
	 * Returns the timestamping authority URI
	 *
	 * @return the timestamping authority URI
	 */
	abstract String timestampingAuthority();

	abstract String timestampingMode();

	abstract int timestampingRetries();

	abstract int timestampingRetryWait();

	abstract String httpProxyHost();

	abstract int httpProxyPort();

	abstract String httpsProxyHost();

	abstract int httpsProxyPort();

	/**
	 * Returns the digest algorithm of the jarsigner command
	 *
	 * @return the digest algorithm of the jarsigner command
	 */
	abstract String digestalg();

	/**
	 * Returns the signature algorithm of the jarsigner command
	 *
	 * @return the signature algorithm of the jarsigner command
	 */
	abstract String sigalg();

	/**
	 * Returns the provider of the jarsigner command
	 *
	 * @return the provider of the jarsigner command
	 */
	abstract String provider();

	/**
	 * Returns the providerArg of the jarsigner command
	 *
	 * @return the providerArg of the jarsigner command
	 */
	abstract String providerArg();

	/**
	 * Returns the keystoreType of the jarsigner command
	 *
	 * @return the keystoreType of the jarsigner command
	 */
	abstract String keystoreType();

	/**
	 * Returns the certificate chain to the jarsigner command
	 *
	 * @return the certificate chain to the jarsigner command
	 */
	abstract Path certchain();

	@AutoValue.Builder
	public static abstract class Builder {
		public abstract JSignInternalCodesigner build();

//		public abstract Builder description(String description);
//
//		public abstract Builder url(String uri);

		public abstract Builder replace(boolean replace);

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

		public abstract Builder timestampingRetries(int timeStampingRetries);

		public abstract Builder timestampingRetryWait(int timeStampingRetryWait);

		/**
		 * Sets the timeout before which the jarsigner process will be killed.
		 *
		 * @return this builder for daisy-chaining.
		 */
		public abstract Builder timeout(long timeout);

		public abstract Builder httpProxyHost(String proxyHost);

		public abstract Builder httpProxyPort(int proxyPort);

		public abstract Builder httpsProxyHost(String proxyHost);

		public abstract Builder httpsProxyPort(int proxyPort);

		abstract Builder digestalg(String digestalg);

		abstract Builder sigalg(String sigalg);

		abstract Builder provider(String provider);

		abstract Builder providerArg(String providerArg);

		abstract Builder keystoreType(String keystoreType);

		abstract Builder certchain(Path certchain);
	}

}
