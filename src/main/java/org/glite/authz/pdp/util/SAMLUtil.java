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

import java.security.NoSuchAlgorithmException;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;

/** Helper methods for creating SAML messages. */
@ThreadSafe
public class SAMLUtil {

    /** Message ID generator. */
    private static IdentifierGenerator idgen;

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<Response> samlResponseBuilder= (SAMLObjectBuilder<Response>) Configuration.getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<Assertion> assertionBuilder= (SAMLObjectBuilder<Assertion>) Configuration.getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<Issuer> issuerBuilder= (SAMLObjectBuilder<Issuer>) Configuration.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<StatusCode> statusCodeBuilder= (SAMLObjectBuilder<StatusCode>) Configuration.getBuilderFactory().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<StatusMessage> statusMessageBuilder= (SAMLObjectBuilder<StatusMessage>) Configuration.getBuilderFactory().getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<Status> statusBuilder= (SAMLObjectBuilder<Status>) Configuration.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);

    /**
     * Creates a SAML response message.
     * 
     * @param inResponseTo
     *            ID of request to which this response corresponds
     * @param issueInstant
     *            issue instant of the response
     * @param assertion
     *            assertion contained in the response
     * @param status
     *            status of the response
     * 
     * @return the constructed response
     */
    public static Response buildSAMLResponse(String inResponseTo,
            DateTime issueInstant, Assertion assertion, Status status) {

        Response samlResponse= samlResponseBuilder.buildObject();
        samlResponse.setID(idgen.generateIdentifier());
        samlResponse.setInResponseTo(inResponseTo);
        samlResponse.setIssueInstant(issueInstant);
        samlResponse.getAssertions().add(assertion);
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /**
     * Creates a SAML assertion.
     * 
     * @param issuerEntityId
     *            ID of the assertion issuer
     * @param issueInstant
     *            issue instant of the assertions
     * @param authzDecisionStatement
     *            authorization decision statement contained in the assertion
     * 
     * @return the constructed assertion
     */
    public static Assertion buildAssertion(String issuerEntityId,
            DateTime issueInstant,
            XACMLAuthzDecisionStatementType authzDecisionStatement) {

        Assertion assertion= assertionBuilder.buildObject();
        assertion.setID(idgen.generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setIssuer(buildIssuer(issuerEntityId));
        assertion.getStatements().add(authzDecisionStatement);
        return assertion;
    }

    /**
     * Builds the Issuer of a SAML message/assertion.
     * 
     * @param entityId
     *            entity ID of the issuer
     * 
     * @return the constructed issuer
     */
    public static Issuer buildIssuer(String entityId) {
        Issuer issuer= issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(entityId);
        return issuer;
    }

    /**
     * Builds a status object.
     * 
     * @param statusCodeValue
     *            {@link StatusCode} value
     * @param statusMessageValue
     *            {@link StatusMessage} value
     * 
     * @return the constructed status
     */
    public static Status buildStatus(String statusCodeValue,
            String statusMessageValue) {
        StatusCode statusCode= statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeValue);

        StatusMessage statusMessage= null;
        if (!Strings.isEmpty(statusMessageValue)) {
            statusMessage= statusMessageBuilder.buildObject();
            statusMessage.setMessage(statusMessageValue);
        }

        Status status= statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        status.setStatusMessage(statusMessage);

        return status;
    }

    static {
        try {
            idgen= new SecureRandomIdentifierGenerator();
        } catch (NoSuchAlgorithmException e) {
            // JVMs are required to support the default ID generation algorithm
        }
    }
}