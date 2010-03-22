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

package org.glite.authz.pdp.util;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;
import org.joda.time.DateTime;
import org.opensaml.xacml.ctx.DecisionType.DECISION;

/** A log entry representing an auditable authorization decision. */
@ThreadSafe
public class AuditLogEntry {

    /** Request timestamp. */
    private long requestTime;

    /** Entity ID of the requester. */
    private String requesterId;

    /** ID of the SAML authorization request message. */
    private String requestId;

    /** ID of the top level policy, or policy set, that resulted in the authorization decision. */
    private String policyId;

    /** Version of the policy, or policy set, that resulted in the authorization decision. */
    private String policyVersion;

    /** The authorization decision. */
    private DECISION policyDecision;

    /** The ID of the SAML response returned from the PDP. */
    private String responseId;

    /**
     * Constructor.
     * 
     * @param requester entity ID of the authorization decision requester
     * @param request ID of the SAML authorization request message
     * @param policy ID of the policy that resulted in the authorization decision
     * @param version version of the policy that resulted in the authorization decision
     * @param decision the authorization decision
     * @param response ID of the SAML authorization response message
     */
    public AuditLogEntry(String requester, String request, String policy, String version, DECISION decision,
            String response) {
        requestTime = new DateTime().toDateTimeISO().getMillis();
        requesterId = Strings.safeTrimOrNullString(requester);
        requestId = Strings.safeTrimOrNullString(request);
        policyId = Strings.safeTrimOrNullString(policy);
        policyVersion = Strings.safeTrimOrNullString(version);
        policyDecision = decision;
        responseId = Strings.safeTrimOrNullString(response);
    }

    /**
     * Gets the authorization decision.
     * 
     * @return authorization decision
     */
    public DECISION getPolicyDecision() {
        return policyDecision;
    }

    /**
     * Gets the ID of the policy that resulted in the authorization decision.
     * 
     * @return ID of the policy that resulted in the authorization decision
     */
    public String getPolicyId() {
        return policyId;
    }

    /**
     * Gets the version of the policy that resulted in the authorization decision.
     * 
     * @return version of the policy that resulted in the authorization decision
     */
    public String getPolicyVersion() {
        return policyVersion;
    }

    /**
     * Get the ID of the SAML authorization decision request message.
     * 
     * @return ID of the SAML authorization decision request message
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Gets the entity ID of the authorization decision requester.
     * 
     * @return entity ID of the authorization decision requester
     */
    public String getRequesterId() {
        return requesterId;
    }

    /**
     * Gets the time, in milliseconds since the Unix epoch, in UTC, that the request was made.
     * 
     * @return time the request was made
     */
    public long getRequestTime() {
        return requestTime;
    }

    /**
     * Gets the ID of the SAML response returned to the requester.
     * 
     * @return ID of the SAML response returned to the requester
     */
    public String getResponseId() {
        return responseId;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder entryString = new StringBuilder();

        entryString.append(getRequestTime());
        entryString.append("|");

        entryString.append(getRequesterId());
        entryString.append("|");

        entryString.append(getRequestId());
        entryString.append("|");

        entryString.append(getPolicyId());
        entryString.append("|");

        entryString.append(getPolicyVersion());
        entryString.append("|");

        entryString.append(getPolicyDecision());
        entryString.append("|");

        entryString.append(getResponseId());
        entryString.append("|");

        return entryString.toString();
    }
}