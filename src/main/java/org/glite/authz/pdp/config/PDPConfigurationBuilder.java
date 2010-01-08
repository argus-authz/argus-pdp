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
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.config.AbstractServiceConfigurationBuilder;
import org.glite.authz.pdp.obligation.ObligationService;
import org.glite.authz.pdp.pip.PolicyInformationPoint;
import org.opensaml.ws.security.SecurityPolicy;

/** A builder of {@link PDPConfiguration}s. */
@NotThreadSafe
public class PDPConfigurationBuilder extends AbstractServiceConfigurationBuilder<PDPConfiguration> {

    /** Registered policy administration point endpoints. */
    private List<String> papEndpoints;

    /** Length of time, in minutes, a policy will be cached. */
    private int policyRetentionInterval;

    /** The ID of the policy set used by this PDP. */
    private String policySetId;

    /** Message security policy used on {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType} messages. */
    private SecurityPolicy authzDecisionQuerySecurityPolicy;
    
    /** Registered policy information points. */
    private List<PolicyInformationPoint> pips;

    /** Obligation processing service. */
    private ObligationService obligationService;

    /** Constructor. */
    public PDPConfigurationBuilder() {
        super();
        papEndpoints = new ArrayList<String>();
        policyRetentionInterval = 60 * 4;
        policySetId = "-1";
        pips = new ArrayList<PolicyInformationPoint>();
    }

    /**
     * Constructor.  The created builder properties are set to the value of given prototypical configuration.
     * 
     * @param prototype the prototypical configuration
     */
    public PDPConfigurationBuilder(PDPConfiguration prototype) {
        super(prototype);
        papEndpoints = prototype.getPAPEndpointss();
        policyRetentionInterval = prototype.getPolicyRetentionInterval();
        policySetId = prototype.getPolicySetId();
    }

    /**
     * Builds a {@link PDPConfiguration} with the current settings of this builder.
     * 
     * @return the constructed configuration
     */
    public PDPConfiguration build() {
        PDPConfiguration config = new PDPConfiguration();
        populateConfiguration(config);
        config.setPAPEndpoints(papEndpoints);
        config.setPolicyRetentionInterval(policyRetentionInterval);
        config.setPolicySetId(policySetId);
        config.setObligationService(obligationService);
        config.setPolicyInformationPoints(pips);
        return config;
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
     * Gets the registered policy administration point endpoint URLs.
     * 
     * @return registered policy administration point endpoint URLs
     */
    public List<String> getPAPEndpoints() {
        return papEndpoints;
    }

    /**
     * Gets the length of time, in minutes, a policy will be cached.
     * 
     * @return length of time, in minutes, a policy will be cached
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
     * Sets the message security policy used for {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType}
     * messages.
     * 
     * @param policy the message security policy
     */
    public void setAuthzDecisionQuerySecurityPolicy(SecurityPolicy policy) {
        authzDecisionQuerySecurityPolicy = policy;
    }

    /**
     * Sets the length of time, in minutes, a policy will be cached.
     * 
     * @param interval length of time, in minutes, a policy will be cached
     */
    public void setPolicyRetentionInterval(int interval) {
        policyRetentionInterval = interval;
    }

    /**
     * Sets the ID of the policy set used by this PDP.
     * 
     * @param id ID of the policy set used by this PDP
     */
    public void setPolicySetId(String id) {
        policySetId = id;
    }
    
    /**
     * Gets the registered policy information points.
     * 
     * @return registered policy information points
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
        return pips;
    }

    /**
     * Gets the obligation processing service.
     * 
     * @return obligation processing service
     */
    public ObligationService getObligationService() {
        return obligationService;
    }

    /**
     * Sets the obligation processing service.
     * 
     * @param service obligation processing service
     */
    public void setObligationService(ObligationService service) {
        obligationService = service;
    }
}