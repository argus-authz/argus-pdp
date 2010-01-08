/*
 * Copyright 2008 Members of the EGEE Collaboration.
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

package org.glite.authz.pdp.obligation;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.pdp.server.AuthorizationRequestServlet.AuthzRequestMessageContext;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.policy.ObligationType;
import org.opensaml.xacml.policy.ObligationsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A service for evaluating the obligations within a context. */
@ThreadSafe
public class ObligationService {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ObligationService.class);

    /** Read/write lock around the registered obligation handlers. */
    private ReentrantReadWriteLock rwLock;

    /** Registered obligation handlers. */
    private Set<AbstractObligationHandler> obligationHandlers;

    /** Constructor. */
    public ObligationService() {
        rwLock = new ReentrantReadWriteLock(true);
        obligationHandlers = new TreeSet<AbstractObligationHandler>(new ObligationHandlerComparator());
    }

    /**
     * Gets the registered obligation handlers.
     * 
     * @return registered obligation handlers
     */
    public Set<AbstractObligationHandler> getObligationHandlers() {
        return Collections.unmodifiableSet(obligationHandlers);
    }

    /**
     * Adds an obligation handler to the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handler the handler to add to the list of registered handlers.
     */
    public void addObligationhandler(AbstractObligationHandler handler) {
        if (handler == null) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.add(handler);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Adds a collection of obligation handler to the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handlers the collection of handlers to add to the list of registered handlers.
     */
    public void addObligationhandler(Collection<AbstractObligationHandler> handlers) {
        if (handlers == null || handlers.isEmpty()) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.addAll(handlers);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Removes an obligation handler from the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handler the handler to remove from the list of registered handlers.
     */
    public void removeObligationHandler(AbstractObligationHandler handler) {
        if (handler == null) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.remove(handler);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Processes the obligations within the effective XACML policy.
     * 
     * This method waits until a read lock is obtained for the set of registered obligation handlers.
     * 
     * @param requestContext the authorization request
     * @param result the result currently be processed
     * 
     * @throws ObligationProcessingException thrown if there is a problem evaluating an obligation
     */
    public void processObligations(AuthzRequestMessageContext requestContext, ResultType result)
            throws ObligationProcessingException {
        Lock readLock = rwLock.readLock();
        readLock.lock();
        try {
            Iterator<AbstractObligationHandler> handlerItr = obligationHandlers.iterator();
            Map<String, ObligationType> effectiveObligations = preprocessObligations(result);
            log.debug("Obligations in effect for this result: {}", effectiveObligations.keySet());

            AbstractObligationHandler handler;
            while (handlerItr.hasNext()) {
                handler = handlerItr.next();
                if (effectiveObligations.containsKey(handler.getObligationId())) {
                    log.debug("Processing obligation {}", handler.getObligationId());
                    handler.evaluateObligation(requestContext, result);
                }
            }
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Pre-processes the obligations returned within the result. This pre-processing determines which obligation
     * handlers are active for a given result. An obligation handler is active if it exists and its {@code Fulfillon}
     * property matches the result {@code Decision}.
     * 
     * @param result the result currently be processed
     * 
     * @return pre-processed obligations indexed by obligation ID
     */
    protected Map<String, ObligationType> preprocessObligations(ResultType result) {
        HashMap<String, ObligationType> effectiveObligations = new HashMap<String, ObligationType>();

        ObligationsType obligations = result.getObligations();
        if (obligations == null || obligations.getObligations().isEmpty()) {
            return effectiveObligations;
        }

        for (ObligationType obligation : obligations.getObligations()) {
            if (isObligationInEffect(obligation, result)) {
                effectiveObligations.put(obligation.getObligationId(), obligation);
            }
        }

        return effectiveObligations;
    }

    /**
     * Determines if an obligation is active given the result of the authorization request.
     * 
     * @param obligation obligation to check
     * @param result authorization request result
     * 
     * @return true if the given obligation is active for the given result
     */
    private boolean isObligationInEffect(ObligationType obligation, ResultType result) {
        if (obligation == null || result == null || result.getDecision() == null) {
            return false;
        }

        switch (obligation.getFulfillOn()) {
            case Deny:
                if (result.getDecision().getDecision() == DECISION.Deny) {
                    return true;
                }
                break;
            case Permit:
                if (result.getDecision().getDecision() == DECISION.Permit) {
                    return true;
                }
                break;
            default:
                return false;
        }
        
        return false;
    }

    /** Comparator used to order obligation handlers by precedence. */
    private class ObligationHandlerComparator implements Comparator<AbstractObligationHandler> {

        /** {@inheritDoc} */
        public int compare(AbstractObligationHandler o1, AbstractObligationHandler o2) {
            if (o1.getHandlerPrecedence() == o2.getHandlerPrecedence()) {
                // If they have the same precedence sort lexigraphically
                return o1.getObligationId().compareTo(o2.getObligationId());
            }

            if (o1.getHandlerPrecedence() < o2.getHandlerPrecedence()) {
                return -1;
            }

            return 1;
        }
    }
}