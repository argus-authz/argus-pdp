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

package org.glite.authz.pdp.policy;

import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.logging.LoggingConstants;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.server.PDPMetrics;
import org.glite.authz.pdp.util.XACMLUtil;

import org.herasaf.xacml.core.policy.PolicyMarshaller;
import org.herasaf.xacml.core.policy.impl.PolicySetType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This policy repository queries a logical, remote, PAP for a policy set. This policy set is then cached and refreshed
 * on a periodic basis.
 */
@ThreadSafe
public class PolicyRepository {

    /** Default {@link PolicyRepository} instance name, {@value} . */
    public static final String DEFAULT_NAME = PolicyRepository.class.getPackage() + "."
            + PolicyRepository.class.getName();

    /** Instantiated policy repositories. */
    private static final HashMap<String, PolicyRepository> REPO_INSTANCES = new HashMap<String, PolicyRepository>();

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PolicyRepository.class);

    /** Policy logger. */
    private final Logger policyLog = LoggerFactory.getLogger(LoggingConstants.POLICY_MESSAGE_CATEGORY);

    /** The name of the repository. */
    private String repositoryName;

    /** Configuration for the daemon. */
    private PDPConfiguration daemonConfig;

    /** Client used to connect to the remote PAP and retrieve the policy set. */
    private PolicyAdministrationPointClient papClient;

    /** Timer controlling the periodic refresh of the policy. */
    private Timer updatePolicyTimer;

    /** Cache copy of the policy. */
    private PolicySetType policySet;

    /**
     * Constructor.
     * 
     * @param pdpConfig configuration for the PDP using this repository
     * @param refreshTimer timer used to schedule policy refresh tasks
     */
    protected PolicyRepository(PDPConfiguration pdpConfig, Timer refreshTimer) {
        daemonConfig = pdpConfig;
        papClient = new PolicyAdministrationPointClient(pdpConfig);

        updatePolicyTimer = refreshTimer;

        long refreshInterval = pdpConfig.getPolicyRetentionInterval() * 60 * 1000;
        updatePolicyTimer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                refreshPolicy();
            }
        }, 0, refreshInterval);
    }

    /**
     * Gets an instance of a policy repository. The repository created is registered under the default repository name
     * and if it does not exist it is created.
     * 
     * @param pdpConfig the PDP configuration
     * @param backgroundTaskTimer timer used for background policy refreshes
     * 
     * @return the policy repository
     */
    public static synchronized PolicyRepository instance(PDPConfiguration pdpConfig, Timer backgroundTaskTimer) {
        return instance(pdpConfig, backgroundTaskTimer, DEFAULT_NAME, true);
    }

    /**
     * Gets an instance of a policy repository.
     * 
     * @param pdpConfig the PDP configuration
     * @param backgroundTaskTimer timer used for background policy refreshes
     * @param name name under which the created policy repository will be registered
     * @param createRepository whether a policy with the given name should be created if it does not yet exists
     * 
     * @return the policy repository, or null if no repository was registered under the given name and was not created
     */
    public static synchronized PolicyRepository instance(PDPConfiguration pdpConfig, Timer backgroundTaskTimer,
            String name, boolean createRepository) {
        PolicyRepository repo = REPO_INSTANCES.get(name);
        if (repo == null && createRepository) {
            repo = new PolicyRepository(pdpConfig, backgroundTaskTimer);
            REPO_INSTANCES.put(name, repo);
        }
        return repo;
    }

    /**
     * Gets the unique name of the repository.
     * 
     * @return unique name of the repository
     */
    public String getName() {
        return repositoryName;
    }

    /**
     * Gets the policy held by this repository.
     * 
     * @return policy held by this repository
     */
    public PolicySetType getPolicy() {
        return policySet;
    }

    /** Refresh the cache copy of the policy. */
    public void refreshPolicy() {
        try {
            log.info("Refreshing authorization policy from remote PAPs");
            org.opensaml.xacml.policy.PolicySetType policySetOM = papClient.retrievePolicySet();
            if (policySetOM != null) {
                policySet = (PolicySetType) PolicyMarshaller.unmarshal(policySetOM.getDOM());
                String policySetId = policySetOM.getPolicySetId();
                String policyVersion = policySetOM.getVersion();
                ((PDPMetrics) daemonConfig.getServiceMetrics()).updatePolicyInformation(policySetId, policyVersion);
                log.info("Loaded version {} of policy {}", policyVersion, policySetId);
                if (policyLog.isInfoEnabled()) {
                    policyLog.info(XACMLUtil.marshall(policySet));
                }
            }
        } catch (Exception e) {
            log.error("Error refreshing policy from remote PAP, continuing to use existing policy.", e);
        }
    }
}