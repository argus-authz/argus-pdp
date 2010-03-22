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

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.pdp.server.AuthorizationRequestServlet.AuthzRequestMessageContext;

/**
 * A Policy Information Point (PIP) gathers information from the current execution environment and populates the
 * subject, environment, and resource information within a {@link Request}.
 * 
 * It is possible that a PIP is not applicable in all cases. For example an application that accepts both X.509
 * certificates and Kerberos ticket as authentication methods might have one PIP for dealing with the certificates and
 * another for dealing with the ticket. Therefore a PIP should indicate that it does not apply to a current request by
 * returning <code>false</code> from the {@link #populateRequest(Request)} method. It should <strong>not</strong> throw
 * an exception in this case.
 * 
 * Some example of what a policy information point may do would be:
 * <ul>
 * <li>evaluate a user's authentication credential in order to populate subject information</li>
 * <li>interrogate the operating system to provide information about the current environment</li>
 * <li>call out to other portions of the application in order to determine the identity of the application and populate
 * resource information</li>
 * </ul>
 */
@ThreadSafe
public interface PolicyInformationPoint {

    /**
     * Gets a unique identifier for this information point.
     * 
     * @return unique identifier for this information point
     */
    public String getId();

    /**
     * Populates the authorization request with information gathered by this information point.
     * 
     * @param requestContext the current request context whose
     *            {@link AuthzRequestMessageContext#getInboundSAMLMessage()} message will be populated by the PIP
     * 
     * @return true if this PIP applies to this request, false if not
     * 
     * @throws PIPProcessingException thrown if there is a problem executing this information point
     */
    public boolean populateRequest(AuthzRequestMessageContext requestContext) throws PIPProcessingException;

    /**
     * Starts the PIP. This is called so that the PIP may initialize itself before its first invocation.
     * 
     * @throws AuthorizationServiceException thrown if there is a problem starting the PIP
     */
    public void start() throws AuthorizationServiceException;

    /**
     * Stops the PIP. This is called so that the PIP may clean up any resource before the service shuts down.
     * 
     * @throws AuthorizationServiceException throw if there is a problem stop the PIP
     */
    public void stop() throws AuthorizationServiceException;
}