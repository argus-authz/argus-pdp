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

import java.io.StringWriter;
import java.util.List;

import javax.xml.bind.JAXBException;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;

import org.herasaf.xacml.core.utils.ContextAndPolicy;
import org.herasaf.xacml.core.utils.ContextAndPolicy.JAXBProfile;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Statement;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.DecisionType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.ctx.StatusType;
import org.opensaml.xacml.policy.EffectType;
import org.opensaml.xacml.policy.ObligationType;
import org.opensaml.xacml.policy.ObligationsType;
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
@ThreadSafe
public class XACMLUtil {

    /** Class logger. */
    private static final Logger LOG= LoggerFactory.getLogger(XACMLUtil.class);

    /** Pool used to parse XML. */
//    private static final BasicParserPool parser;

    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<XACMLAuthzDecisionStatementType> authzStatementBuilder= (SAMLObjectBuilder<XACMLAuthzDecisionStatementType>) Configuration.getBuilderFactory().getBuilder(XACMLAuthzDecisionStatementType.TYPE_NAME_XACML20);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<ResponseType> xacmlResponseBuilder= (XACMLObjectBuilder<ResponseType>) Configuration.getBuilderFactory().getBuilder(ResponseType.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<DecisionType> decisionBuilder= (XACMLObjectBuilder<DecisionType>) Configuration.getBuilderFactory().getBuilder(org.opensaml.xacml.ctx.DecisionType.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<ResultType> resultBuilder= (XACMLObjectBuilder<ResultType>) Configuration.getBuilderFactory().getBuilder(ResultType.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<ObligationsType> obligationsBuilder= (XACMLObjectBuilder<ObligationsType>) Configuration.getBuilderFactory().getBuilder(ObligationsType.SCHEMA_TYPE_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<ObligationType> obligationBuilder= (XACMLObjectBuilder<ObligationType>) Configuration.getBuilderFactory().getBuilder(ObligationType.SCHEMA_TYPE_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<StatusCodeType> statusCodeBuilder= (XACMLObjectBuilder<StatusCodeType>) Configuration.getBuilderFactory().getBuilder(StatusCodeType.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static XACMLObjectBuilder<StatusType> statusBuilder= (XACMLObjectBuilder<StatusType>) Configuration.getBuilderFactory().getBuilder(StatusType.DEFAULT_ELEMENT_NAME);

    /**
     * Builds an authorization decision statement.
     * 
     * @param authzRequest
     *            original authorization request context, or null if it is not
     *            to be returned in the response
     * @param authzResponse
     *            the authorization decision response
     * 
     * @return the constructed authorization decision statement
     */
    public static XACMLAuthzDecisionStatementType buildAuthZDecisionStatement(
            RequestType authzRequest, ResponseType authzResponse) {
        XACMLAuthzDecisionStatementType authzStatement= authzStatementBuilder.buildObject(Statement.DEFAULT_ELEMENT_NAME,
                                                                                          XACMLAuthzDecisionStatementType.TYPE_NAME_XACML20);
        authzStatement.setRequest(authzRequest);
        authzStatement.setResponse(authzResponse);
        return authzStatement;
    }

    /**
     * Builds a request type corresponding to the original XACML request.
     * 
     * @param authzRequest
     *            the original authorization request
     * 
     * @return the constructed request or null if no return context was required
     */
    public static RequestType buildRequest(
            XACMLAuthzDecisionQueryType authzRequest) {
        if (!authzRequest.isReturnContext()) {
            return null;
        }

        Element requestElem= authzRequest.getRequest().getDOM();
        if (requestElem == null) {
            Marshaller marshaller= Configuration.getMarshallerFactory().getMarshaller(authzRequest);
            try {
                requestElem= marshaller.marshall(authzRequest);
            } catch (MarshallingException e) {
                LOG.error("Unable to marshall XACML request context", e);
                return null;
            }
        }

        Element requestElemClone= (Element) requestElem.cloneNode(true);
        Unmarshaller unmarshaller= Configuration.getUnmarshallerFactory().getUnmarshaller(requestElem);
        try {
            RequestType xacmlRequest= (RequestType) unmarshaller.unmarshall(requestElemClone);
            return xacmlRequest;
        } catch (UnmarshallingException e) {
            LOG.error("Error unmarshalling clone of XACML request context element",
                      e);
            return null;
        }
    }

    /**
     * Creates a XACML response message.
     * 
     * @param result
     *            the result of the request
     * 
     * @return the constructed response
     */
    public static ResponseType buildResponse(ResultType result) {
        ResponseType response= xacmlResponseBuilder.buildObject();
        response.setResult(result);
        return response;
    }

    /**
     * Creates a Result.
     * 
     * @param resourceId
     *            ID of the resource
     * @param decision
     *            result decision
     * @param obligationCollection
     *            result obligations
     * @param status
     *            result status
     * 
     * @return the constructed result
     */
    public static ResultType buildResult(String resourceId, DECISION decision,
            List<ObligationType> obligationCollection, StatusType status) {

        DecisionType xacmlDecision= decisionBuilder.buildObject();
        xacmlDecision.setDecision(decision);

        ResultType result= resultBuilder.buildObject();

        result.setResourceId(Strings.safeTrimOrNullString(resourceId));

        result.setDecision(xacmlDecision);
        result.setStatus(status);

        if (obligationCollection != null && !obligationCollection.isEmpty()) {
            ObligationsType obligations= obligationsBuilder.buildObject();
            obligations.getObligations().addAll(obligationCollection);
            result.setObligations(obligations);
        }

        return result;
    }

    /**
     * Transforms a HERAS obligation in to an OpenSAML obligation.
     * 
     * <em>NOTE:</em> Obligations with attribute assignments are not currently
     * supported.
     * 
     * @param herasObligation
     *            HERAS obligation to be transformed
     * 
     * @return the OpenSAML obligation
     */
    public static ObligationType buildObligation(
            org.herasaf.xacml.core.policy.impl.ObligationType herasObligation) {
        if (herasObligation == null) {
            return null;
        }

        if (herasObligation.getAttributeAssignments() != null
                && !herasObligation.getAttributeAssignments().isEmpty()) {
            LOG.error("Obligations with attribute assignments are nor currently supported");
            return null;
        }

        ObligationType obligation= obligationBuilder.buildObject();

        obligation.setObligationId(herasObligation.getObligationId());
        switch (herasObligation.getFulfillOn()) {
        case DENY:
            obligation.setFulfillOn(EffectType.Deny);
            break;
        case PERMIT:
            obligation.setFulfillOn(EffectType.Permit);
            break;
        }

        // TODO attribute assignement

        return obligation;
    }

    /**
     * Creates a status.
     * 
     * @param statusCodeValue
     *            value of the {@link StatusCodeType}
     * 
     * @return the constructed status
     */
    public static StatusType buildStatus(String statusCodeValue) {
        StatusCodeType statusCode= statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeValue);

        StatusType status= statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        return status;
    }

    /**
     * Marshalls a JAX element.
     * 
     * @param jaxbElement
     *            element to marshall
     * 
     * @return the marshalled form of the element or null if he element could
     *         not be marshalled
     */
    public static String marshall(Object jaxbElement) {
        if (jaxbElement == null) {
            return null;
        }

        try {
            javax.xml.bind.Marshaller marshaller= ContextAndPolicy.getMarshaller(JAXBProfile.POLICY);
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT,
                                   true);
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FRAGMENT,
                                   true);
            StringWriter writer= new StringWriter();
            marshaller.marshal(jaxbElement, writer);
            return writer.toString();
        } catch (JAXBException e) {
            LOG.error("Unable to log policy to be used for authorization decision",
                      e);
            return null;
        }
    }

//    static {
//        parser= new BasicParserPool();
//        parser.setMaxPoolSize(50);
//    }
}