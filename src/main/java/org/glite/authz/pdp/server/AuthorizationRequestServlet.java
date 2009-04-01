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

package org.glite.authz.pdp.server;

import java.io.IOException;
import java.util.Timer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.http.BaseHttpServlet;
import org.glite.authz.common.logging.LoggingConstants;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.policy.PolicyRepository;
import org.glite.authz.pdp.util.AuditLogEntry;
import org.glite.authz.pdp.util.SAMLUtil;
import org.glite.authz.pdp.util.XACMLUtil;
import org.herasaf.xacml.core.combiningAlgorithm.CombiningAlgorithm;
import org.herasaf.xacml.core.context.RequestInformation;
import org.herasaf.xacml.core.context.impl.DecisionType;
import org.herasaf.xacml.core.context.impl.RequestType;
import org.herasaf.xacml.core.policy.impl.PolicySetType;
import org.herasaf.xacml.core.utils.ContextAndPolicy;
import org.joda.time.DateTime;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml1.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** PDP Servlet. */
@ThreadSafe
public class AuthorizationRequestServlet extends BaseHttpServlet {

    /** Name of the servlet context attribute where this servlet expects to find a {@link Timer}. */
    public static final String TIMER_ATTRIB = "org.glite.authz.pdp.server.timmer";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AuthorizationRequestServlet.class);

    /** Authorization decision audit log. */
    private final Logger auditLog = LoggerFactory.getLogger(LoggingConstants.AUDIT_CATEGORY);

    /** Protocol message log. */
    private final Logger protocolLog = LoggerFactory.getLogger(LoggingConstants.PROTOCOL_MESSAGE_CATEGORY);

    /** Policy log. */
    private final Logger policyLog = LoggerFactory.getLogger(LoggingConstants.POLICY_MESSAGE_CATEGORY);

    /** PDP configuration. */
    private PDPConfiguration pdpConfig;

    /** Timer that may be used for scheduling background tasks. */
    private Timer taskTimer;

    /** Resolver used to get the security policy for incoming messages. */
    private SecurityPolicyResolver messageSecurityPolicyResolver;

    /** The decoder used to decode incoming message. */
    private HTTPSOAP11Decoder messageDecoder;

    /** The encoder used to write outgoing messages. */
    private HTTPSOAP11Encoder messageEncoder;

    /** Repository of XACML policies. */
    private PolicyRepository policyRepo;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        pdpConfig = (PDPConfiguration) getServletContext().getAttribute(PDPConfiguration.BINDING_NAME);
        if (pdpConfig == null) {
            throw new ServletException("Unable to initialize, no configuration available in servlet context");
        }

        taskTimer = (Timer) getServletContext().getAttribute(TIMER_ATTRIB);
        if (taskTimer == null) {
            throw new ServletException("Unable to initialize, no Timer available in servlet context");
        }

        messageSecurityPolicyResolver = new StaticSecurityPolicyResolver(pdpConfig
                .getAuthzDecisionQuerySecurityPolicy());

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(pdpConfig.getMaxRequests());

        messageDecoder = new HTTPSOAP11Decoder(parserPool);

        messageEncoder = new HTTPSOAP11Encoder();

        policyRepo = new PolicyRepository(pdpConfig, taskTimer);
    }

    /** {@inheritDoc} */
    protected void doPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        AuthzRequestMessageContext messageContext = new AuthzRequestMessageContext();

        Response samlResponse;
        try {
            decodeMessage(messageContext, httpRequest, httpResponse);
            samlResponse = evaluateRequest(messageContext);
        } catch (AuthorizationServiceException e) {
            pdpConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
            log.error("Error processing authorization request.", e);
            samlResponse = buildSAMLResponse(messageContext, DecisionType.INDETERMINATE,
                    StatusCodeType.SC_PROCESSING_ERROR);
        }

        encodeMessage(messageContext, samlResponse, httpRequest, httpResponse);
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "POST";
    }

    /**
     * Decodes a message in to the given message context.
     * 
     * @param messageContext message context into which the decoded information should be added.
     * @param httpRequest incoming HTTP request
     * @param httpResponse outgoing HTTP response
     * 
     * @throws AuthorizationServiceException thrown if there is a problem decoding message
     */
    protected void decodeMessage(AuthzRequestMessageContext messageContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws AuthorizationServiceException {
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));
        messageContext
                .setOutboundMessageTransport(new HttpServletResponseAdapter(httpResponse, httpRequest.isSecure()));
        messageContext.setSecurityPolicyResolver(messageSecurityPolicyResolver);

        try {
            log.debug("Decoding incomming message");
            messageDecoder.decode(messageContext);
            if (protocolLog.isInfoEnabled()) {
                protocolLog.info("Incomming SOAP message\n{}", XMLHelper.prettyPrintXML(messageContext
                        .getInboundMessage().getDOM()));
            }
        } catch (MessageDecodingException e) {
            throw new AuthorizationServiceException("Unable to decode incoming request", e);
        } catch (SecurityException e) {
            throw new AuthorizationServiceException("Incoming request does not meeting security requirements", e);
        }
    }

    /**
     * Encodes an outgoing response.
     * 
     * @param messageContext message context for the current message
     * @param samlResponse response to encode
     * @param httpRequest incoming HTTP request
     * @param httpResponse outgoing HTTP response
     */
    protected void encodeMessage(AuthzRequestMessageContext messageContext, Response samlResponse,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        messageContext.setOutboundSAMLMessageIssueInstant(new DateTime());
        messageContext.setOutboundMessageIssuer(pdpConfig.getEntityId());
        messageContext.setOutboundSAMLMessage(samlResponse);
        messageContext.setOutboundSAMLMessageId(messageContext.getOutboundSAMLMessage().getID());

        log.debug("Encoding response");
        try {
            messageEncoder.encode(messageContext);
            if (protocolLog.isDebugEnabled()) {
                protocolLog.debug("SOAP response\n{}", XMLHelper.prettyPrintXML(messageContext.getOutboundMessage()
                        .getDOM()));
            }
            pdpConfig.getServiceMetrics().incrementTotalServiceRequests();
            writeAuditLogEntry(messageContext);
        } catch (MessageEncodingException e) {
            log.error("Unable to encoding response.", e);
        }
    }

    /**
     * Handles the incoming authorization request. This method also sets the {@link AuthzRequestMessageContext#policy}
     * property.
     * 
     * @param messageContext incoming message context
     * 
     * @throws AuthorizationServiceException thrown if there is a problem evaluating the authorization decision request
     */
    protected Response evaluateRequest(AuthzRequestMessageContext messageContext) throws AuthorizationServiceException {
        PolicySetType policy = policyRepo.getPolicy();

        if (policy == null) {
            throw new AuthorizationServiceException(
                    "No policy available by which the incomming request may be evaluated");
        }
        if (policyLog.isDebugEnabled()) {
            policyLog.debug("Evaluating authorization request against policy\n{}", XACMLUtil.marshall(policy));
        }
        messageContext.setAuthorizationPolicy(policy);

        try {
            log.debug("Evaluating request {} from {} against version {} of authorization policy {}", new Object[] {
                    messageContext.getInboundSAMLMessageId(), messageContext.getInboundMessageIssuer(),
                    policy.getVersion(), policy.getPolicySetId() });
            RequestInformation reqInfo = new RequestInformation(null, null);
            CombiningAlgorithm combiningAlgo = policy.getCombiningAlg();
            DecisionType decision = combiningAlgo.evaluate(getXacmlRequest(messageContext), policy, reqInfo);
            log
                    .debug(
                            "A decision of {} was reached when evaluating authorization request {} against version {} of policy {}",
                            new Object[] { decision.toString(), messageContext.getInboundSAMLMessageId(),
                                    policy.getVersion(), policy.getPolicySetId() });
            return buildSAMLResponse(messageContext, decision, StatusCodeType.SC_OK);
        } catch (Exception e) {
            pdpConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
            log.error("Error evaluating policy", e);
            return buildSAMLResponse(messageContext, DecisionType.INDETERMINATE, StatusCodeType.SC_PROCESSING_ERROR);
        }
    }

    /**
     * Creates a HERAS-AF XACML request from a SAML authorization decision query.
     * 
     * @param messageContext current message context
     * 
     * @return the XACML request
     * 
     * @throws AuthorizationServiceException thrown if there is a problem converting the incoming message XML in to a
     *             XACML request
     */
    @SuppressWarnings("unchecked")
    protected RequestType getXacmlRequest(AuthzRequestMessageContext messageContext)
            throws AuthorizationServiceException {
        XACMLAuthzDecisionQueryType authzRequest = messageContext.getInboundSAMLMessage();
        try {
            Unmarshaller unmarshaller = ContextAndPolicy.getUnmarshaller(ContextAndPolicy.JAXBProfile.REQUEST_CTX);
            JAXBElement<RequestType> reqTypeElem = (JAXBElement<RequestType>) unmarshaller.unmarshal(authzRequest
                    .getRequest().getDOM());
            return reqTypeElem.getValue();
        } catch (JAXBException e) {
            log.error("Unable to convert SAML/XACML authorization request into HERASAF request context", e);
            throw new AuthorizationServiceException("Invalid request message.", e);
        }
    }

    /**
     * Creates the SAML response given the decision reached by the PDP. This method also sets the
     * {@link AuthzRequestMessageContext#decision} property.
     * 
     * @param messageContext current message context
     * @param herasDecision decision reached by the PDP
     * @param statusCodeValue status code for the decision
     * 
     * @return the created SAML response
     */
    protected Response buildSAMLResponse(AuthzRequestMessageContext messageContext, DecisionType herasDecision,
            String statusCodeValue) {

        DECISION decision;
        if (herasDecision == DecisionType.DENY) {
            decision = DECISION.Deny;
        } else if (herasDecision == DecisionType.PERMIT) {
            decision = DECISION.Permit;
        } else if (herasDecision == DecisionType.NOT_APPLICABLE) {
            decision = DECISION.NotApplicable;
        } else {
            decision = DECISION.Indeterminate;
        }
        messageContext.setAuthorizationDecision(decision);

        XACMLAuthzDecisionStatementType authzStatement = XACMLUtil.buildAuthZDecisionStatement(XACMLUtil
                .buildRequest(messageContext.getInboundSAMLMessage()), XACMLUtil.buildResponse(XACMLUtil
                .buildStatus(statusCodeValue), decision));

        Assertion samlAssertion = SAMLUtil.buildAssertion(pdpConfig.getEntityId(), messageContext
                .getOutboundSAMLMessageIssueInstant(), authzStatement);
        return SAMLUtil.buildSAMLResponse(messageContext.getInboundSAMLMessageId(), messageContext
                .getOutboundSAMLMessageIssueInstant(), samlAssertion, SAMLUtil
                .buildStatus(StatusCode.SUCCESS_URI, null));
    }

    /**
     * Writes out an audit log entry.
     * 
     * @param messageContext current message context
     */
    protected void writeAuditLogEntry(AuthzRequestMessageContext messageContext) {
        String policyId = "";
        String policyVersion = "";
        if (messageContext.getAuthorizationPolicy() != null) {
            policyId = messageContext.getAuthorizationPolicy().getPolicySetId();
            policyVersion = messageContext.getAuthorizationPolicy().getVersion();
        }

        AuditLogEntry auditEntry = new AuditLogEntry(messageContext.getInboundMessageIssuer(), messageContext
                .getInboundSAMLMessageId(), policyId, policyVersion, messageContext.getAuthorizationDecision(),
                messageContext.getOutboundSAMLMessageId());

        auditLog.info(auditEntry.toString());
    }

    /** Message context for {@link XACMLAuthzDecisionQueryType} requests. */
    private static class AuthzRequestMessageContext extends
            BasicSAMLMessageContext<XACMLAuthzDecisionQueryType, Response, NameID> {

        /** Policy used to render the authorization decision. */
        private PolicySetType policy;

        /** The authorization decision. */
        private DECISION decision;

        /**
         * Gets the policy used to reach the authorization decision.
         * 
         * @return policy used to reach the authorization decision
         */
        public PolicySetType getAuthorizationPolicy() {
            return policy;
        }

        /**
         * Sets the policy used to reach the authorization decision.
         * 
         * @param authzPolicy policy used to reach the authorization decision
         */
        public void setAuthorizationPolicy(PolicySetType authzPolicy) {
            policy = authzPolicy;
        }

        /**
         * Gets the authorization decision.
         * 
         * @return the authorization decision
         */
        public DECISION getAuthorizationDecision() {
            return decision;
        }

        /**
         * Sets the authorization decision.
         * 
         * @param authzDecision the authorization decision
         */
        public void setAuthorizationDecision(DECISION authzDecision) {
            decision = authzDecision;
        }
    }
}