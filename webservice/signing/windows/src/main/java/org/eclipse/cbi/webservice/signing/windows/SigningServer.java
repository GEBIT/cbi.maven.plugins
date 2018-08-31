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

import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.cbi.util.ProcessExecutor;
import org.eclipse.cbi.util.PropertiesReader;
import org.eclipse.cbi.webservice.server.EmbeddedServer;
import org.eclipse.cbi.webservice.server.EmbeddedServerProperties;
import org.eclipse.cbi.webservice.servlet.RequestFacade;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;

public class SigningServer {

	@Option(name = "-c", usage = "configuration file")
	private String configurationFilePath = "windows-signing-service.properties";

	@Argument
	private List<String> arguments = new ArrayList<String>();

	public static void main(String[] args) throws Exception {
		new SigningServer().doMain(FileSystems.getDefault(), args);
	}

	private void doMain(FileSystem fs, String[] args) throws Exception, InterruptedException {
		if (parseCmdLineArguments(fs, args)) {
			final Path confPath = fs.getPath(configurationFilePath);
			PropertiesReader properties = PropertiesReader.create(confPath);
			final EmbeddedServerProperties serverConf = new EmbeddedServerProperties(properties);
			final Path tempFolder = serverConf.getTempFolder();

			final Codesigner codesigner;
			if ("jsign".equalsIgnoreCase(properties.getString("windows.signer"))) {
				final JSignProperties conf = new JSignProperties(properties);
				codesigner = JSignCodesigner.builder()
						.processExecutor(new ProcessExecutor.BasicImpl())
						.jsignjar(conf.getJsignjar())
						.keystore(conf.getKeystore())
						.keystoreAlias(conf.getKeystoreAlias())
						.keystorePassword(conf.getKeystorePassword())
						.keystoreType(conf.getKeystoreType())
						.keyfile(conf.getKeyfile())
						.keyfilePassword(conf.getKeyfilePassword())
						.timeout(conf.getTimeout())
						.timestampingAuthority(conf.getTimeStampingAuthority())
						.timestampingMode(conf.getTimeStampingMode())
						.httpProxyHost(conf.getHttpProxyHost())
						.httpProxyPort(conf.getHttpProxyPort())
						.replace(conf.getReplace())
						.digestalg(conf.getDigestalg())
						.certfile(conf.getCertfile())
						.description(conf.getDescription())
						.url(conf.getURL())
						.build();

			} else if ("jsign-internal".equalsIgnoreCase(properties.getString("windows.signer"))) {

				final JSignInternalProperties conf = new JSignInternalProperties(properties);
				codesigner = JSignInternalCodesigner.builder()
						.keystore(conf.getKeystore())
						.keystoreAlias(conf.getKeystoreAlias())
						.keystorePassword(conf.getKeystorePassword())
						.keystoreType(conf.getKeystoreType())
						.timeout(conf.getTimeout())
						.timestampingAuthority(conf.getTimeStampingAuthority())
						.timestampingMode(conf.getTimeStampingMode())
						.timestampingRetries(conf.getTimeStampingRetries())
						.timestampingRetryWait(conf.getTimeStampingRetryWait())
						.httpProxyHost(conf.getHttpProxyHost())
						.httpProxyPort(conf.getHttpProxyPort())
						.httpsProxyHost(conf.getHttpsProxyHost())
						.httpsProxyPort(conf.getHttpsProxyPort())
						.provider(conf.getProvider())
						.providerArg(conf.getProviderArg())
						.replace(conf.getReplace())
						.sigalg(conf.getSigalg())
						.digestalg(conf.getDigestalg())
						.certchain(conf.getCertchain())
						.description(conf.getDescription())
						.url(conf.getURL())
						.build();

			} else {

				final OSSLSigncodeProperties conf = new OSSLSigncodeProperties(properties);

				codesigner = OSSLCodesigner.builder()
						.processExecutor(new ProcessExecutor.BasicImpl())
						.osslsigncode(conf.getOSSLSigncode())
						.timeout(conf.getTimeout())
						.pkcs12(conf.getPKCS12())
						.pkcs12Password(conf.getPKCS12Password())
						.timestampURI(conf.getTimestampURI())
						.tempFolder(tempFolder)
						.description(conf.getDescription())
						.uri(conf.getURI())
						.build();
			}

			final SigningServlet codeSignServlet = SigningServlet.builder()
					.codesigner(codesigner)
					.requestFacadeBuilder(RequestFacade.builder(tempFolder))
					.build();

			final EmbeddedServer server = EmbeddedServer.builder()
					.port(serverConf.getServerPort())
					.accessLogFile(serverConf.getAccessLogFile())
					.servicePathSpec(serverConf.getServicePathSpec())
					.appendServiceVersionToPathSpec(serverConf.isServiceVersionAppendedToPathSpec())
					.servlet(codeSignServlet)
					.tempFolder(tempFolder)
					.log4jConfiguration(confPath).build();

			server.start();
		}
	}

	private boolean parseCmdLineArguments(FileSystem fs, String[] args) {
		CmdLineParser parser = new CmdLineParser(this);
		parser.getProperties().withUsageWidth(80);

		try {
			// parse the arguments.
			parser.parseArgument(args);
		} catch (CmdLineException e) {
			System.err.println(e.getMessage());
			System.err.println("java -jar windows-signing-service-x.y.z.jar [options...]");
			// print the list of available options
			parser.printUsage(System.err);
			System.err.println();

			// print option sample. This is useful some time
			System.err.println("  Example: java -jar windows-signing-service-x.y.z.jar "
					+ parser.printExample(OptionHandlerFilter.REQUIRED));

			return false;
		}

		if (!Files.exists(fs.getPath(configurationFilePath))) {
			System.err.println("Configuration file does not exist: '" + configurationFilePath + "'");
			parser.printUsage(System.err);
			System.err.println();
		}

		return true;
	}
}
