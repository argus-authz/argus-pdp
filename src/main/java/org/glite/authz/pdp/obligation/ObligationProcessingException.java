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

package org.glite.authz.pdp.obligation;

import org.glite.authz.common.AuthorizationServiceException;

/** Thrown when an {@link AbstractObligationHandler} fails to handle an obligation. */
public class ObligationProcessingException extends AuthorizationServiceException {

    /** Serial version UID. */
    private static final long serialVersionUID = -7787659159540080804L;

    /** Constructor. */
    public ObligationProcessingException() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     */
    public ObligationProcessingException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * 
     * @param wrappedException exception to be wrapped by this one
     */
    public ObligationProcessingException(Exception wrappedException) {
        super(wrappedException);
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     * @param wrappedException exception to be wrapped by this one
     */
    public ObligationProcessingException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}