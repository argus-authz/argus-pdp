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

package org.glite.authz.pdp.server;

import java.io.PrintWriter;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.ServiceMetrics;
import org.glite.authz.common.util.Strings;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;

/** Extension to {@link ServiceMetrics} that adds addition information about the current policy. */
@ThreadSafe
public class PDPMetrics extends ServiceMetrics {

    /** Instant the policy was fetched from the PAP, in milliseconds in the local timezone. */
    private long policyLoadTimeMillis;

    /** ID of the policy currently being used by the PDP. */
    private String policyId;

    /** Version of the policy currently being used by the PDP. */
    private String policyVersion;

    /** Constructor. */
    public PDPMetrics() {
        super(Version.getServiceName(), Version.getServiceVersion());
    }

    /**
     * Gets the ID of the policy currently used by the PDP.
     * 
     * @return the policyId ID of the policy currently used by the PDP
     */
    public String getPolicyId() {
        return policyId;
    }

    /**
     * Gets the instant the policy was fetched from the PAP, in milliseconds (epoch) in the local timezone.
     * 
     * @return the instant the policy was fetched from the PAP
     */
    public long getPolicyLoadInstant() {
        return policyLoadTimeMillis;
    }

    /**
     * Gets the version of the policy currently used by the PDP.
     * 
     * @return version of the policy currently used by the PDP
     */
    public String getPolicyVersion() {
        return policyVersion;
    }

    /**
     * Updates the information on the policy currently used by the PDP. This updates the policy ID and version to the
     * given values and sets the policy load instant to the time when this method was invoked.
     * 
     * @param id ID of the policy
     * @param version version of the policy
     */
    public synchronized void updatePolicyInformation(String id, String version) {
        policyId = Strings.safeTrimOrNullString(id);
        policyLoadTimeMillis = System.currentTimeMillis();
        policyVersion = Strings.safeTrimOrNullString(version);
    }

    /**
     * {@inheritDoc}
     * 
     * This method also adds the following lines.
     * <ul>
     * <li>PolicyLoadTime: <i>policy_load_time_iso_utc</i></li>
     * <li>PolicyLoadTimeMillis: <i>policy_load_timemillis</i></li>
     * <li>CurrentPolicy: <i>current_policy_id</i></li>
     * <li>CurrentPolicyVersion: <i>current_policy_version</i></li>
     * </ul>
     */
    public void printServiceMetrics(PrintWriter writer) {
        super.printServiceMetrics(writer);
        DateTime policyLoadTime= null;
        if (policyLoadTimeMillis > 0) {
            policyLoadTime= new DateTime(policyLoadTimeMillis).withChronology(ISOChronology.getInstanceUTC());
        }
        writer.println("PolicyLoadTime: " + policyLoadTime);
        writer.println("PolicyLoadTimeMillis: " + policyLoadTimeMillis);
        writer.println("CurrentPolicy: " + policyId);
        writer.println("CurrentPolicyVersion: " + policyVersion);
    }
}