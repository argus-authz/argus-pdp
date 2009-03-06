/*
 * Copyright 2009 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pdp.server;

import org.opensaml.Configuration;
import org.opensaml.saml1.core.AuthorizationDecisionStatement;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.DecisionType;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.ctx.StatusType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/** A helper class for creating XACML messages. */
public class XACMLUtil {

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(XACMLUtil.class);

    /**
     * Builds an authorization decision statement.
     * 
     * @param authzRequest original authorization request context, or null if it is not to be returned in the response
     * @param authzResponse the authorization decision response
     * 
     * @return the constructed authorization decision statement
     */
    @SuppressWarnings("unchecked")
    public static XACMLAuthzDecisionStatementType buildAuthZDecisionStatement(RequestType authzRequest,
            ResponseType authzResponse) {
        XACMLObjectBuilder<XACMLAuthzDecisionStatementType> authzStatementBuilder = (XACMLObjectBuilder<XACMLAuthzDecisionStatementType>) Configuration
                .getBuilderFactory().getBuilder(AuthorizationDecisionStatement.TYPE_NAME);
        XACMLAuthzDecisionStatementType authzStatement = authzStatementBuilder.buildObject();
        authzStatement.setRequest(authzRequest);
        authzStatement.setResponse(authzResponse);
        return authzStatement;
    }

    /**
     * Builds a request type corresponding to the original XACML request.
     * 
     * @param authzRequest the original authorization request
     * 
     * @return the constructed request or null if no return context was required
     */
    public static RequestType buildRequest(XACMLAuthzDecisionQueryType authzRequest) {
        if (!authzRequest.isReturnContext()) {
            return null;
        }

        Element requestElem = authzRequest.getRequest().getDOM();
        if (requestElem == null) {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authzRequest);
            try {
                requestElem = marshaller.marshall(authzRequest);
            } catch (MarshallingException e) {
                LOG.error("Unable to marshall XACML request context", e);
                return null;
            }
        }

        Element requestElemClone = (Element) requestElem.cloneNode(true);
        Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(requestElem);
        try {
            RequestType xacmlRequest = (RequestType) unmarshaller.unmarshall(requestElemClone);
            return xacmlRequest;
        } catch (UnmarshallingException e) {
            LOG.error("Error unmarshalling clone of XACML request context element", e);
            return null;
        }
    }

    /**
     * Creates a XACML response message.
     * 
     * @param status status message
     * @param decision the authorization decision
     * 
     * @return the constructed response
     */
    @SuppressWarnings("unchecked")
    public static ResponseType buildResponse(StatusType status, DECISION decision) {
        XACMLObjectBuilder<DecisionType> decisionBuilder = (XACMLObjectBuilder<DecisionType>) Configuration
                .getBuilderFactory().getBuilder(org.opensaml.xacml.ctx.DecisionType.TYPE_NAME);

        DecisionType xacmlDecision = decisionBuilder.buildObject();
        xacmlDecision.setDecision(decision);

        XACMLObjectBuilder<ResultType> resultBuilder = (XACMLObjectBuilder<ResultType>) Configuration
                .getBuilderFactory().getBuilder(ResultType.TYPE_NAME);
        ResultType result = resultBuilder.buildObject();
        result.setDecision(xacmlDecision);
        result.setStatus(status);

        // TODO obligation support
        // result.setObligations(obligations);

        XACMLObjectBuilder<ResponseType> xacmlResponseBuilder = (XACMLObjectBuilder<ResponseType>) Configuration
                .getBuilderFactory().getBuilder(ResponseType.TYPE_NAME);
        ResponseType response = xacmlResponseBuilder.buildObject();
        response.setResult(result);
        return response;
    }

    /**
     * Creates a status.
     * 
     * @param statusCodeValue value of the {@link StatusCodeType}
     * 
     * @return the constructed status
     */
    @SuppressWarnings("unchecked")
    public static StatusType buildStatus(String statusCodeValue) {
        XACMLObjectBuilder<StatusCodeType> statusCodeBuilder = (XACMLObjectBuilder<StatusCodeType>) Configuration
                .getBuilderFactory().getBuilder(StatusCodeType.TYPE_NAME);
        StatusCodeType statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeValue);

        XACMLObjectBuilder<StatusType> statusBuilder = (XACMLObjectBuilder<StatusType>) Configuration
                .getBuilderFactory().getBuilder(StatusType.TYPE_NAME);
        StatusType status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        return status;
    }
}