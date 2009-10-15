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

package org.glite.authz.pdp.policy;

import java.util.Timer;
import java.util.TimerTask;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.logging.LoggingConstants;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.server.PDPMetrics;
import org.glite.authz.pdp.util.XACMLUtil;
import org.herasaf.xacml.core.policy.PolicyConverter;
import org.herasaf.xacml.core.policy.impl.PolicySetType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This policy repository queries a logical, remote, PAP for a policy set. This policy set is then cached and refreshed
 * on a periodic basis.
 */
@ThreadSafe
public class PolicyRepository {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PolicyRepository.class);

    /** Policy logger. */
    private final Logger policyLog = LoggerFactory.getLogger(LoggingConstants.POLICY_MESSAGE_CATEGORY);

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
    public PolicyRepository(PDPConfiguration pdpConfig, Timer refreshTimer) {
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
     * Gets the policy held by this repository.
     * 
     * @return policy held by this repository
     */
    public PolicySetType getPolicy() {
        return policySet;
    }

    /** Refresh the cache copy of the policy. */
    private void refreshPolicy() {
        try {
            log.info("Refreshing authorization policy from remote PAPs");
            org.opensaml.xacml.policy.PolicySetType policySetOM = papClient.retrievePolicySet();
            if (policySetOM != null) {
                policySet = (PolicySetType) PolicyConverter.unmarshal(policySetOM.getDOM());
                String policySetId = policySetOM.getPolicySetId();
                String policyVersion = policySetOM.getVersion();
                ((PDPMetrics)daemonConfig.getServiceMetrics()).updatePolicyInformation(policySetId, policyVersion);
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