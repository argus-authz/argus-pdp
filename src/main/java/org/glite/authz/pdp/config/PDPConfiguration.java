/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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

package org.glite.authz.pdp.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractServiceConfiguration;
import org.glite.authz.pdp.obligation.ObligationService;
import org.glite.authz.pdp.pip.PolicyInformationPoint;
import org.glite.authz.pdp.server.PDPMetrics;
import org.opensaml.ws.security.SecurityPolicy;

/** Policy decision point configuration. */
@ThreadSafe
public class PDPConfiguration extends AbstractServiceConfiguration {

    /** Registered policy administration point endpoints. */
    private List<String> papEndpoints;

    /** Length of time, in minutes, a policy will be cached. */
    private int policyRetentionInterval;

    /** The ID of the policy set used by this PDP. */
    private String policySetId;

    /** Message security policy used on {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType} messages. */
    private SecurityPolicy authzDecisionQuerySecurityPolicy;
    
    /** Registered {@link PolicyInformationPoint}s. */
    private List<PolicyInformationPoint> pips;
    
    /** Obligation processing service. */
    private ObligationService obligationService;

    /** Constructor. */
    protected PDPConfiguration() {
        super(new PDPMetrics());
        policyRetentionInterval = 0;
        policySetId = null;
        papEndpoints = null;
        authzDecisionQuerySecurityPolicy = null;
        pips = new ArrayList<PolicyInformationPoint>();
    }

    /**
     * Gets the message security policy used for {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType}
     * messages.
     * 
     * @return the message security policy
     */
    public SecurityPolicy getAuthzDecisionQuerySecurityPolicy() {
        return authzDecisionQuerySecurityPolicy;
    }

    /**
     * Gets the immutable list of registered policy administration point endpoints.
     * 
     * @return registered policy administration point endpoints
     */
    public List<String> getPAPEndpointss() {
        return papEndpoints;
    }

    /**
     * Gets the interval, in minutes, between policy refreshes.
     * 
     * @return interval, in minutes, between policy refreshes
     */
    public int getPolicyRetentionInterval() {
        return policyRetentionInterval;
    }

    /**
     * Gets the ID of the policy set used by this PDP.
     * 
     * @return ID of the policy set used by this PDP
     */
    public String getPolicySetId() {
        return policySetId;
    }
    
    /**
     * Gets the policy information points meant to be applied to each request.
     * 
     * @return policy information points meant to be applied to each request
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
        return pips;
    }
    
    /**
     * Gets the service used to process response obligations.
     * 
     * @return service used to process response obligations
     */
    public ObligationService getObligationService() {
        return obligationService;
    }

    /**
     * Sets the message security policy used for {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType}
     * messages.
     * 
     * @param policy the message security policy
     */
    protected final synchronized void setAuthzDecisionQuerySecurityPolicy(SecurityPolicy policy) {
        if (authzDecisionQuerySecurityPolicy != null) {
            throw new IllegalStateException(
                    "Authorization decision security policy has already been set, it may not be changed");
        }
        authzDecisionQuerySecurityPolicy = policy;
    }

    /**
     * Sets the list of registered policy administration point endpoints.
     * 
     * @param paps list of registered policy administration point endpoints
     */
    protected final synchronized void setPAPEndpoints(List<String> paps) {
        if (papEndpoints != null) {
            throw new IllegalStateException("Policy administration points have already been set, it may not changed");
        }

        if (paps != null) {
            papEndpoints = Collections.unmodifiableList(paps);
        } else {
            papEndpoints = Collections.emptyList();
        }

    }

    /**
     * Sets the interval, in minutes, between policy refreshes.
     * 
     * @param interval interval, in minutes, between policy refreshes
     */
    protected final synchronized void setPolicyRetentionInterval(int interval) {
        if (policyRetentionInterval != 0) {
            throw new IllegalStateException("Policy refresh interval has already been set, it may not be changed");
        }
        policyRetentionInterval = interval;
    }

    /**
     * Sets the ID of the policy set used by this PDP.
     * 
     * @param id ID of the policy set used by this PDP
     */
    protected final synchronized void setPolicySetId(String id) {
        if (policySetId != null) {
            throw new IllegalStateException("Policy set ID has already been set, it may not changed");
        }
        policySetId = id;
    }
    
    /**
     * Sets the policy information points.
     * 
     * @param policyInformationPoints policy information point
     */
    protected final synchronized void setPolicyInformationPoints(List<PolicyInformationPoint> policyInformationPoints) {
        if (policyInformationPoints == null || policyInformationPoints.isEmpty()) {
            return;
        }

        if (pips != null) {
            throw new IllegalArgumentException(
                    "Policy Information Points have already been set, they may not be changed");
        }
        pips = Collections.unmodifiableList(policyInformationPoints);
    }
    
    /**
     * Sets the obligation processing service.
     * 
     * @param service obligation processing service
     */
    protected final synchronized void setObligationService(ObligationService service) {
        if (service == null) {
            return;
        }

        if (obligationService != null) {
            throw new IllegalArgumentException("Obligation service has already been set, they may not be changed");
        }
        obligationService = service;
    }
}