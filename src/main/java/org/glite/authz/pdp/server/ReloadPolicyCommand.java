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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.http.AbstractAdminCommand;
import org.glite.authz.pdp.policy.PolicyRepository;


/** An admin command that causes the PDP to reload its policy. */
public class ReloadPolicyCommand extends AbstractAdminCommand {

    /** Serial version UID. */
    private static final long serialVersionUID = 4302446834211259498L;
    
    /** Policy repository whose policies will be reloaded. */
    private PolicyRepository policyRepository;
    
    /**
     * Constructor.
     * 
     * @param repository the repository whose policies will be reloaded
     */
    public ReloadPolicyCommand(PolicyRepository repository){
        super("/reloadPolicy");
        
        if(repository == null){
            throw new IllegalArgumentException("Policy repository may not be null");
        }
        policyRepository = repository;
    }
    
    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        policyRepository.refreshPolicy();
        resp.setStatus(HttpServletResponse.SC_OK);
    }
}