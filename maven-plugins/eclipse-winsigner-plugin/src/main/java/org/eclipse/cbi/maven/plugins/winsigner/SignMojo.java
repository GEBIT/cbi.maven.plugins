/*******************************************************************************
 * Copyright (c) 2013, 2015 Eclipse Foundation and others
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Caroline McQuatt, Mike Lim - initial implementation
 *   Mikael Barbero - refactoring with WindowsExeSigner
 *******************************************************************************/
package org.eclipse.cbi.maven.plugins.winsigner;

import java.io.File;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
import org.eclipse.cbi.common.http.ApacheHttpClientPostFileSender;
import org.eclipse.cbi.common.http.HttpPostFileSender;
import org.eclipse.cbi.maven.common.MavenLogger;

/**
 * Signs project main and attached artifact using
 * <a href="http://wiki.eclipse.org/IT_Infrastructure_Doc#Sign_my_plugins.2FZIP_files.3F">Eclipse winsigner webservice</a>.
 *
 * @goal sign
 * @phase package
 * @requiresProject
 * @description runs the eclipse signing process
 */
public class SignMojo extends AbstractMojo {

	private static final String ECLIPSEC_EXE = "eclipsec.exe";

	private static final String ECLIPSE_EXE = "eclipse.exe";

	/**
     * The signing service URL for signing Windows binaries
     *
     * <p>The signing service should return a signed exe file.</p>
     *
     * <p>The Official Eclipse signer service URL as described in the
     * <a href="http://wiki.eclipse.org/IT_Infrastructure_Doc#Sign_my_plugins.2FZIP_files.3F">
     * wiki</a>.</p>
     *
     * <p><b>Configuration via Maven commandline</b></p>
     * <pre>-Dcbi.winsigner.signerUrl=http://localhost/winsign.php</pre>
     *
     * <p><b>Configuration via pom.xml</b></p>
     * <pre>{@code
     * <configuration>
     *   <signerUrl>http://localhost/winsign</signerUrl>
     * </configuration>
     * }</pre>
     *
     * @parameter property="cbi.winsigner.signerUrl" default-value="http://build.eclipse.org:31338/winsign.php" )
     * @required
     * @since 1.0.4
     */
    private String signerUrl;

    /**
     * Name of configured credentials to use.
     * @parameter property="cbi.serverId"
     * @since 1.2.0
     */
    private String serverId;

    /**
     * Maven build directory
     *
     * @parameter property="project.build.directory"
     * @readonly
     * @since 1.0.4
     * @deprecated not used anymore. Use {@code java.io.tmpdir} property instead.
     */
    @SuppressWarnings("unused")
	@Deprecated
    private File workdir;

    /**
     * A list of full executable paths to be signed
     *
     * <p>If configured only these executables will be signed.</p>
     * <p><b><i>
     *    NOTE: If this is configured "baseSearchDir" and "fileNames"
     *    do NOT need to be configured.
     * </i></b></p>
     *
     * <p><b>Configuration via pom.xml</b></p>
     * <pre>{@code
     * <configuration>
     *   <signFiles>
     *     <signFile>}${project.build.directory}/products/org.eclipse.sdk.ide/win32/win32/x86/eclipse/eclipse.exe{@code</signFile>
     *     <signFile>}${project.build.directory}/products/org.eclipse.sdk.ide/win32/win32/x86/eclipse/eclipsec.exe{@code</signFile>
     *     <signFile>}${project.build.directory}/products/org.eclipse.sdk.ide/win32/win32/x86_64/eclipse/eclipse.exe{@code</signFile>
     *     <signFile>}${project.build.directory}/products/org.eclipse.sdk.ide/win32/win32/x86_64/eclipse/eclipsec.exe{@code</signFile>
     *   </signFiles>
     * </configuration>
     * }</pre>
     *
     * @parameter property="signFiles"
     * @since 1.0.4
     */
    private String[] signFiles;

    /**
     * The base directory to search for executables to sign
     *
     * <p>If NOT configured baseSearchDir is ${project.build.directory}/products/</p>
     *
     * @parameter property="baseSearchDir" default-value="${project.build.directory}/products/"
     * @since 1.0.4
     */
    private String baseSearchDir;

    /**
     * List of file names to sign
     *
     * <p>If NOT configured 'eclipse.exe' and 'eclipsec.exe' are signed.</p>
     *
     * @parameter property="fileNames"
     * @since 1.0.4
     */
    private Set<String> fileNames;

    /**
     * Continue the build even if signing fails
     *
     * <p><b>Configuration via Maven commandline</b></p>
     * <pre>-DcontinueOnFail=true</pre>
     *
     * <p><b>Configuration via pom.xml</b></p>
     * <pre>{@code
     * <configuration>
     *   <continueOnFail>true</continueOnFail>
     * </configuration>
     * }</pre>
     *
     * @parameter property="continueOnFail" default-value="false"
     * @since 1.0.5
     */
    private boolean continueOnFail;

    /**
     * Number of times to retry signing if server fails to sign
     *
     * @parameter property="retryLimit" default-value="3"
     * @since 1.1.0
     */
    private int retryLimit;

    /**
     * Number of seconds to wait before retrying to sign
     *
     * @parameter property="retryTimer" default-value="30"
     * @since 1.1.0
     */
    private int retryTimer;

    /**
     * Application name to be added to the signature
     *
     * @parameter property="cbi.winsigner.name" default-value="false"
     * @since 1.2.0
     */
    private String name;

    /**
     * Application url to be added to the signature
     *
     * @parameter property="cbi.winsigner.url" default-value="false"
     * @since 1.2.0
     */
    private String url;

    /**
     * Skips the execution of this plugin
     *
     * @parameter property="cbi.winsigner.skip" default-value="false"
     * @since 1.2.0
     */
    private boolean skip;

    /**
     * @parameter default-value="${session}"
     * @readonly
     */
    private MavenSession session;

    /**
     * @component role="org.apache.maven.settings.crypto.SettingsDecrypter"
     */
    private SettingsDecrypter settingsDecrypter;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping executable signing");
            return;
        }

        String user = null;
        String password = null;
        if (serverId != null) {
            Server server = session.getSettings().getServer(serverId);
            if (server == null) {
                throw new MojoExecutionException("Cannot find server settings for '" + serverId + "'.");
            }

            // decrypt password
            SettingsDecryptionResult result = settingsDecrypter.decrypt( new DefaultSettingsDecryptionRequest( server ) );
            server = result.getServer();

            user = server.getUsername();
            password = server.getPassword();
            if (user == null || password == null) {
                throw new MojoExecutionException("Server settings for '" + serverId + "' has no user and/or password.");
            }
        }

        List<NameValuePair> additionalParams = new ArrayList<>();
        if (name != null) {
        	additionalParams.add(new BasicNameValuePair("name", name));
        }
        if (url != null ) {
        	additionalParams.add(new BasicNameValuePair("url", url));
        }
    	final HttpPostFileSender signer = new ApacheHttpClientPostFileSender(URI.create(signerUrl), new MavenLogger(getLog()), user, password, additionalParams.toArray(new NameValuePair[additionalParams.size()]));
    	WindowsExeSigner.Builder winExeSignerBuilder = WindowsExeSigner.builder(signer).logOn(getLog()).maxRetry(retryLimit).waitBeforeRetry(retryTimer, TimeUnit.SECONDS);
    	if (continueOnFail) {
    		winExeSignerBuilder.continueOnFail();
    	}
    	WindowsExeSigner exeSigner = winExeSignerBuilder.build();

    	if (signFiles != null && signFiles.length != 0) {
    		//exe paths are configured
    		Set<Path> exePaths = new LinkedHashSet<>();
        	for (String path : signFiles) {
        		exePaths.add(FileSystems.getDefault().getPath(path));
        	}
        	exeSigner.signExecutables(exePaths);
    	} else {
    		//perform search
    		Set<PathMatcher> pathMatchers = getPathMatchers(FileSystems.getDefault(), fileNames, getLog());
    		Path baseSearchDirPath = FileSystems.getDefault().getPath(baseSearchDir);
    		if (!Files.exists(baseSearchDirPath)) {
    			getLog().debug("Basedir " + baseSearchDir + " does not exist");
    			return;
    		}
    		exeSigner.signExecutables(baseSearchDirPath, pathMatchers);
    	}
    }

    static Set<PathMatcher> getPathMatchers(FileSystem fs, Set<String> fileNames, Log log) {
		final Set<PathMatcher> pathMatchers = new LinkedHashSet<>();

		if (fileNames == null || fileNames.isEmpty()) {
			pathMatchers.add(fs.getPathMatcher("glob:**" + fs.getSeparator() + ECLIPSE_EXE));
			pathMatchers.add(fs.getPathMatcher("glob:**" + fs.getSeparator() + ECLIPSEC_EXE));
		} else {
			for (String filename : fileNames) {
				pathMatchers.add(fs.getPathMatcher("glob:**" + filename));
			}
		}
		return pathMatchers;
	}
}
