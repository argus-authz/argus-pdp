/*
 * Copyright 2008 EGEE Collaboration
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

package org.glite.authz.pdp.policy;

import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.AuthzServiceConstants;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClient;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.policy.IdReferenceType;
import org.opensaml.xacml.policy.PolicySetType;
import org.opensaml.xacml.profile.saml.XACMLPolicyQueryType;
import org.opensaml.xacml.profile.saml.XACMLPolicyStatementType;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A simple client to the Policy Administration Point. */
@ThreadSafe
public class PolicyAdministrationPointClient {

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(PolicyAdministrationPointClient.class);

    /** PDP configuration. */
    private PDPConfiguration pdpConfig;

    /** Generator of SAML message IDs. */
    private IdentifierGenerator idGen;

    /** Builder of {@link Envelope}s. */
    private SOAPObjectBuilder<Envelope> envelopeBuilder;

    /** Builder of {@link Body}s. */
    private SOAPObjectBuilder<Body> bodyBuilder;

    /** Builder of {@link XACMLPolicyQueryType}s. */
    private SAMLObjectBuilder<XACMLPolicyQueryType> policyQueryBuilder;

    /** Builder of {@link Issuer}s. */
    private SAMLObjectBuilder<Issuer> issuerBuilder;
    
    /** Builder of policy set ID references. */
    private XACMLObjectBuilder<IdReferenceType> idReferenceBuilder;

    /**
     * Constructor.
     * 
     * @param config PDP configuration
     */
    @SuppressWarnings("unchecked")
    public PolicyAdministrationPointClient(PDPConfiguration config) {
        pdpConfig = config;

        idGen = new RandomIdentifierGenerator();

        envelopeBuilder = (SOAPObjectBuilder<Envelope>) Configuration.getBuilderFactory()
                .getBuilder(Envelope.TYPE_NAME);
        bodyBuilder = (SOAPObjectBuilder<Body>) Configuration.getBuilderFactory().getBuilder(Body.TYPE_NAME);
        policyQueryBuilder = (SAMLObjectBuilder<XACMLPolicyQueryType>) Configuration.getBuilderFactory().getBuilder(
                XACMLPolicyQueryType.TYPE_NAME_XACML20);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) Configuration.getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME);
        idReferenceBuilder = (XACMLObjectBuilder<IdReferenceType>) Configuration.getBuilderFactory().getBuilder(IdReferenceType.POLICY_SET_ID_REFERENCE_ELEMENT_NAME);
    }

    /**
     * Makes a policy query to a PAP and retrieves the policies for the given request context.
     * 
     * @return a collection of {@link org.opensaml.xacml.policy.PolicyType}s and
     *         {@link org.opensaml.xacml.policy.PolicySetType}s or null if no policies could be retrieved
     * 
     * @throws AuthorizationServiceException thrown if there is a problem retrieving the policies
     */
    public PolicySetType retrievePolicySet() throws AuthorizationServiceException {
        SOAPMessageContext messageContext = buildMessageContext();
        Envelope soapResponse = null;
        SOAPClient soapClient = pdpConfig.getSoapClient();
        for (String pap : pdpConfig.getPolicyAdministrationPoints()) {
            try {
                soapClient.send(pap, messageContext);
                if (messageContext.getInboundMessage() != null) {
                    // TODO check to make sure we didn't get an error status back
                    soapResponse = (Envelope) messageContext.getInboundMessage();
                    break;
                }
            } catch (SOAPClientException e) {
                log.warn("Unable to complete request to PAP endpoint: " + pap, e);
            } catch (SecurityException e) {
                log.warn("Poliqy query to PAP endpoint " + pap
                        + " returned a message that did not meet security requirements", e);
            }
        }

        if (soapResponse != null) {
            Response samlResponse = (Response) soapResponse.getBody().getOrderedChildren().get(0);
            System.out.println("\n\n\n" + XMLHelper.nodeToString(samlResponse.getDOM()) + "\n\n\n");
            return extractPolicySet(samlResponse);
        } else {
            return null;
        }
    }

    /**
     * Builds up the SOAP request message context.
     * 
     * @return the SOAP request context
     */
    protected SOAPMessageContext buildMessageContext() {
        Envelope outboundMessage = buildPolicyRequest();
        HttpSOAPRequestParameters requestParams = new HttpSOAPRequestParameters(
                "http://www.oasis-open.org/committees/security");

        // TODO set security policy resolver
        BasicSOAPMessageContext messageContext = new BasicSOAPMessageContext();
        messageContext.setCommunicationProfileId(AuthzServiceConstants.XACML_SAML_PROFILE_URI);
        messageContext.setOutboundMessage(outboundMessage);
        messageContext.setOutboundMessageIssuer(pdpConfig.getEntityId());
        messageContext.setSOAPRequestParameters(requestParams);

        return messageContext;
    }

    /**
     * Builds the policy request message to be sent to the policy administration point.
     * 
     * @return the policy request message to be sent to the policy administration point
     */
    protected Envelope buildPolicyRequest() {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(pdpConfig.getEntityId());
        
        IdReferenceType policySetReference = idReferenceBuilder.buildObject(IdReferenceType.POLICY_SET_ID_REFERENCE_ELEMENT_NAME);
        policySetReference.setValue(pdpConfig.getPolicySetId());        
        
        XACMLPolicyQueryType policyQuery = policyQueryBuilder.buildObject(
                XACMLPolicyQueryType.DEFAULT_ELEMENT_NAME_XACML20, XACMLPolicyQueryType.TYPE_NAME_XACML20);
        policyQuery.setID(idGen.generateIdentifier());
        policyQuery.setIssueInstant(new DateTime());
        policyQuery.setIssuer(issuer);
        policyQuery.getPolicySetIdReferences().add(policySetReference);

        // TODO signature support

        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(policyQuery);

        Envelope env = envelopeBuilder.buildObject();
        env.setBody(body);

        return env;
    }

    /**
     * Extract the policies returned from the policy query.
     * 
     * @param samlResponse the response to the policy query
     * 
     * @return a collection of {@link org.opensaml.xacml.policy.PolicySetType} and
     *         {@link org.opensaml.xacml.policy.PolicyType} objects returned in the response
     */
    protected PolicySetType extractPolicySet(Response samlResponse) {
        if (samlResponse != null) {
            List<Assertion> assertions = samlResponse.getAssertions();
            if (!assertions.isEmpty()) {
                if (assertions.size() > 1) {
                    log.warn("PAP returned a response with more than one assertion, only the first will be used");
                }
                List<Statement> policyStatements = assertions.get(0).getStatements(
                        XACMLPolicyStatementType.TYPE_NAME_XACML20);
                if (!policyStatements.isEmpty()) {
                    if (policyStatements.size() > 1) {
                        log.warn("PAP returned more than one policy statement, only the first will be used");
                    }
                    XACMLPolicyStatementType policyStatement = (XACMLPolicyStatementType) policyStatements.get(0);
                    List<PolicySetType> policySets = policyStatement.getPolicySets();
                    if(policySets != null && policySets.size() > 1){
                        log.warn("PAP return more than one policy set, only the first will be used");
                    }
                    if(policySets.size() > 0){
                        return policySets.get(0);
                    }
                }
            }
        }
        return null;
    }
}