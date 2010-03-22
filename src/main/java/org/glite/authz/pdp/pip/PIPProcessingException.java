/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
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
 */

package org.glite.authz.pdp.pip;

import org.glite.authz.common.AuthorizationServiceException;

/** Thrown when an {@link PolicyInformationPoint} fails. */
public class PIPProcessingException extends AuthorizationServiceException {

    /** Serial version UID. */
    private static final long serialVersionUID = 6616470982835428775L;

    /** Constructor. */
    public PIPProcessingException() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     */
    public PIPProcessingException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * 
     * @param wrappedException exception to be wrapped by this one
     */
    public PIPProcessingException(Exception wrappedException) {
        super(wrappedException);
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     * @param wrappedException exception to be wrapped by this one
     */
    public PIPProcessingException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}