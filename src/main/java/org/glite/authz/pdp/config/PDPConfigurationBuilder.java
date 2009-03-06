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

import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.util.Strings;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.soap.client.SOAPClient;

/** A builder of {@link PDPConfiguration}s. */
@NotThreadSafe
public class PDPConfigurationBuilder extends AbstractConfigurationBuilder<PDPConfiguration> {

    /** EntitID of the PEP daemon. */
    private String entityId;

    /** Hostname or IP address upon which the daemon will listen. */
    private String hostname;

    /** Port upon which the daemon will listen. */
    private int port;
    
    /** Port number upon which the PDP shutdown service listens. */
    private int shutdownPort;

    /** Max number of requests the daemon will enqueue. */
    private int maxRequestQueueSize;
    
    /** Registered policy administration point endpoints. */
    private List<String> policyAdministrationPoints;

    /** Length of time, in minutes, a policy will be cached. */
    private int policyRetentionInterval;

    /** The ID of the policy set used by this PDP. */
    private String policySetId;

    /** SOAP client used by the daemon to communicate with PDPs. */
    private SOAPClient soapClient;

    /** Message security policy used on {@link org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType} messages. */
    private SecurityPolicy authzDecisionQuerySecurityPolicy;

    /** Constrcutor. */
    public PDPConfigurationBuilder() {
        super();
        hostname = "0.0.0.0";
        port = 8080;
        shutdownPort = 8081;
        maxRequestQueueSize = 500;
        policyAdministrationPoints = new ArrayList<String>();
        policyRetentionInterval = 60 * 4;
        policySetId = "-1";
    }
    
    public PDPConfigurationBuilder(PDPConfiguration prototype){
        super(prototype);
        entityId = prototype.getEntityId();
        hostname = prototype.getHostname();
        port = prototype.getPort();
        shutdownPort = prototype.getShutdownPort();
        maxRequestQueueSize = prototype.getMaxRequestQueueSize();
        policyAdministrationPoints = prototype.getPolicyAdministrationPoints();
        policyRetentionInterval = prototype.getPolicyRetentionInterval();
        policySetId = prototype.getPolicySetId();
        soapClient = prototype.getSoapClient();
    }
    
    /**
     * Builds a {@link PDPConfiguration} with the current settings of this builder.
     * 
     * @return the constructed configuration
     */
    public PDPConfiguration build() {
        PDPConfiguration config = new PDPConfiguration();
        populateConfiguration(config);
        config.setEntityId(entityId);
        config.setHostname(hostname);
        config.setPort(port);
        config.setShutdownPort(shutdownPort);
        config.setMaxRequestQueueSize(maxRequestQueueSize);
        config.setPolicyAdministrationPoints(policyAdministrationPoints);
        config.setPolicyRetentionInterval(policyRetentionInterval);
        config.setPolicySetId(policySetId);
        config.setSoapClient(soapClient);
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
     * Gets the Entity ID of the PEP daemon.
     * 
     * @return entity ID of the PEP daemon
     */
    public String getEntityId() {
        return entityId;
    }
    
    /**
     * Gets the host to which the PEP daemon will bind.
     * 
     * @return host to which the PEP daemon will bind
     */
    public String getHost() {
        return hostname;
    }

    /**
     * Gets the max number of requests the daemon will enqueue.
     * 
     * @return max number of requests the daemon will enqueue
     */
    public int getMaxRequestQueueSize() {
        return maxRequestQueueSize;
    }

    /**
     * Gets the registered policy administration point endpoint URLs.
     * 
     * @return registered policy administration point endpoint URLs
     */
    public List<String> getPolicyAdministrationPoints() {
        return policyAdministrationPoints;
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
     * Gets the port upon which the daemon will listen.
     * 
     * @return port upon which the daemon will listen
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
     * Gets the SOAP client used by the daemon to communicate with PDPs.
     * 
     * @return SOAP client used by the daemon to communicate with PDPs
     */
    public SOAPClient getSOAPClient() {
        return soapClient;
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
     * Sets the Entity ID of the PEP daemon.
     * 
     * @param id Entity ID of the PEP daemon
     */
    public void setEntityId(String id) {
        entityId = Strings.safeTrimOrNullString(id);
    }

    /**
     * Sets the hostname or IP address upon which the daemon will listen.
     * 
     * @param newHost hostname or IP address upon which the daemon will listen
     */
    public void setHost(String newHost) {
        if (Strings.isEmpty(newHost)) {
            throw new IllegalArgumentException("Host may not be null or empty");
        }
        hostname = newHost;
    }

    /**
     * Sets the max number of requests the daemon will enqueue.
     * 
     * @param max max number of requests the daemon will enqueue
     */
    public void setMaxRequestQueueSize(int max) {
        maxRequestQueueSize = max;
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
     * Sets the port upon which the daemon will listen.
     * 
     * @param newPort port upon which the daemon will listen
     */
    public void setPort(int newPort) {
        port = newPort;
    }

    /**
     * Sets the port number upon which the PDP shutdown service listens.
     * 
     * @param port port number upon which the PDP shutdown service listens
     */
    public void setShutdownPort(int port) {
        shutdownPort = port;
    }

    /**
     * Sets the SOAP client used by the daemon to communicate with PDPs.
     * 
     * @param client SOAP client used by the daemon to communicate with PDPs
     */
    public void setSoapClient(SOAPClient client) {
        if (client == null) {
            throw new IllegalArgumentException("SOAP client may not be null");
        }
        soapClient = client;
    }
}