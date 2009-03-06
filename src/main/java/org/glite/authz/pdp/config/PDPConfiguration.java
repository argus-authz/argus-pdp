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

package org.glite.authz.pdp.config;

import java.util.Collections;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractConfiguration;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.soap.client.SOAPClient;

/** Policy decision point configuration. */
@ThreadSafe
public class PDPConfiguration extends AbstractConfiguration {

    /** The entity ID for the PDP service. */
    private String entityId;

    /** Hostname upon which the PDP service listens. */
    private String hostname;

    /** Port number upon which the PDP service listens. */
    private int port;

    /** Port number upon which the PDP shutdown service listens. */
    private int shutdownPort;

    /** Max number of requests that will be queued if all PDP processing threads are busy. */
    private int maxRequestQueueSize;

    /** Registered policy administration point endpoints. */
    private List<String> policyAdministrationPoints;

    /** Length of time, in minutes, a policy will be cached. */
    private int policyRetentionInterval;

    /** The ID of the policy set used by this PDP. */
    private String policySetId;

    /** SOAP client used to communicate with the PAP. */
    private SOAPClient soapClient;

    /** Message security policy used on {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType} messages. */
    private SecurityPolicy authzDecisionQuerySecurityPolicy;

    /** Constructor. */
    protected PDPConfiguration() {
        super();
        hostname = null;
        port = 0;
        shutdownPort = 0;
        maxRequestQueueSize = 0;
        policyRetentionInterval = 0;
        policySetId = null;
        policyAdministrationPoints = null;
        soapClient = null;
        authzDecisionQuerySecurityPolicy = null;
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
     * Gets the entity ID of the PDP service.
     * 
     * @return entity ID of the PDP service
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * Gets the hostname upon which the PDP service listens.
     * 
     * @return hostname upon which the PDP service listens
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Gets the maximum number of requests the PDP will queue up if all of its request processing threads are busy.
     * 
     * @return maximum number of requests the PDP will queue up if all of its request processing threads are busy
     */
    public int getMaxRequestQueueSize() {
        return maxRequestQueueSize;
    }

    /**
     * Gets the immutable list of registered policy administration point endpoints.
     * 
     * @return registered policy administration point endpoints
     */
    public List<String> getPolicyAdministrationPoints() {
        return policyAdministrationPoints;
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
     * Gets the port number upon which the PDP service listens.
     * 
     * @return the port number upon which the PDP service listens
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets the port number upon which the PDP shutdown service listens.
     * 
     * @return port number upon which the PDP shutdown service listens
     */
    public int getShutdownPort() {
        return shutdownPort;
    }

    /**
     * Gets the SOAP client used to communicate with the PAP.
     * 
     * @return SOAP client used to communicate with the PAP
     */
    public SOAPClient getSoapClient() {
        return soapClient;
    }

    /**
     * Sets the message security policy used for {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType}
     * messages.
     * 
     * @param policy the message security policy
     */
    protected synchronized final void setAuthzDecisionQuerySecurityPolicy(SecurityPolicy policy) {
        if (authzDecisionQuerySecurityPolicy != null) {
            throw new IllegalStateException(
                    "Authorization decision security policy has already been set, it may not be changed");
        }
        authzDecisionQuerySecurityPolicy = policy;
    }

    /**
     * Sets the entity ID of the PDP service.
     * 
     * @param id entity ID of the PDP service
     */
    protected synchronized final void setEntityId(String id) {
        if (entityId != null) {
            throw new IllegalStateException("Entity ID has already been set, it may not be changed");
        }
        entityId = id;
    }

    /**
     * Sets the hostname upon which the PDP service listens.
     * 
     * @param newHost hostname upon which the PDP service listens
     */
    protected synchronized final void setHostname(String newHost) {
        if (hostname != null) {
            throw new IllegalArgumentException("Hostname has already been set, it may be changed");
        }
        hostname = newHost;
    }

    /**
     * Sets the maximum number of requests the PDP will queue up if all of its request processing threads are busy.
     * 
     * @param max maximum number of requests the PDP will queue up if all of its request processing threads are busy
     */
    protected synchronized final void setMaxRequestQueueSize(int max) {
        if (maxRequestQueueSize != 0) {
            throw new IllegalStateException("Max request size has already been set, it may not be changed");
        }
        maxRequestQueueSize = max;
    }

    /**
     * Sets the list of registered policy administration point endpoints.
     * 
     * @param paps list of registered policy administration point endpoints
     */
    protected synchronized final void setPolicyAdministrationPoints(List<String> paps) {
        if (policyAdministrationPoints != null) {
            throw new IllegalStateException("Policy administration points have already been set, it may not changed");
        }

        if (paps != null) {
            policyAdministrationPoints = Collections.unmodifiableList(paps);
        } else {
            policyAdministrationPoints = Collections.emptyList();
        }

    }

    /**
     * Sets the interval, in minutes, between policy refreshes.
     * 
     * @param interval interval, in minutes, between policy refreshes
     */
    protected synchronized final void setPolicyRetentionInterval(int interval) {
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
    protected synchronized final void setPolicySetId(String id) {
        if (policySetId != null) {
            throw new IllegalStateException("Policy set ID has already been set, it may not changed");
        }
        policySetId = id;
    }

    /**
     * Sets the port number upon which the PDP service listens.
     * 
     * @param newPort number upon which the PDP service listens
     */
    protected synchronized final void setPort(int newPort) {
        if (port != 0) {
            throw new IllegalStateException("Service port number has already been set, it may not be changed");
        }
        port = newPort;
    }

    /**
     * Sets the port number upon which the PDP shutdown service listens.
     * 
     * @param port the shutdownPort to set
     */
    protected synchronized final void setShutdownPort(int port) {
        if (shutdownPort != 0) {
            throw new IllegalStateException("Shutdown service port has already been set, it may not be changed");
        }

        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Shutdown port must be between 1 and 65535");
        }
        shutdownPort = port;
    }

    /**
     * Sets the SOAP client used to communicate with the PAP.
     * 
     * @param client SOAP client used to communicate with the PAP
     */
    protected synchronized final void setSoapClient(SOAPClient client) {
        if (soapClient != null) {
            throw new IllegalStateException("SOAP client has already been set, it may not be changed");
        }
        soapClient = client;
    }
}