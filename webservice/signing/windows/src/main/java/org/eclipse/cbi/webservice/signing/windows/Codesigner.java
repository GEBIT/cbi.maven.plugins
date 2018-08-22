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

import java.io.IOException;
import java.nio.file.Path;

/**
 * Interfact to the actual signing implementations.
 */
public interface Codesigner {

	/**
	 * Sign a given file in place.
	 *
	 * @param file the file to be signed
	 * @throws IOException if anything goes wrong
	 */
	public void sign(Path file) throws IOException;
}
