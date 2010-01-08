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

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;
import org.glite.authz.pdp.server.AuthorizationRequestServlet.AuthzRequestMessageContext;
import org.opensaml.xacml.ctx.ResultType;

/**
 * Base class for all obligation handlers.
 * 
 * Handlers are executed in order of precedence. Handlers with a higher precedence are executed before those with a
 * lower precedence. Handlers with the same precedence are executed in random order.
 * 
 * Obligation handlers <strong>must</strong> be stateless.
 */
@ThreadSafe
public abstract class AbstractObligationHandler {

    /** ID of the handled obligation. */
    private String id;

    /** Precedence of this handler. */
    private int precedence;

    /**
     * Constructor. Obligation has the lowest precedence, zero.
     * 
     * @param obligationId ID of the handled obligation
     */
    protected AbstractObligationHandler(String obligationId) {
        this(obligationId, 0);
    }

    /**
     * Constructor.
     * 
     * @param obligationId ID of the handled obligation
     * @param handlerPrecedence precedence of this handler, must be 0 or greater
     */
    protected AbstractObligationHandler(String obligationId, int handlerPrecedence) {
        id = Strings.safeTrimOrNullString(obligationId);
        if (id == null) {
            throw new IllegalArgumentException("Provided obligation ID may not be null or empty");
        }

        if (handlerPrecedence < 0) {
            throw new IllegalArgumentException("Handler precedence must be 0 or greater");
        }
        precedence = handlerPrecedence;
    }

    /**
     * Gets the ID of the handled obligation.
     * 
     * @return ID of the handled obligation
     */
    public String getObligationId() {
        return id;
    }

    /**
     * Gets the precedence of the handler.
     * 
     * @return precedence of the handler
     */
    public int getHandlerPrecedence() {
        return precedence;
    }

    /**
     * Evaluates the obligation represented by this handler.
     * 
     * @param requestContext the authorization request
     * @param result the result being processed
     * 
     * @throws ObligationProcessingException thrown if there is a problem evaluating this handler
     */
    public abstract void evaluateObligation(AuthzRequestMessageContext requestContext, ResultType result)
            throws ObligationProcessingException;

    /** {@inheritDoc} */
    public int hashCode() {
        return getObligationId().hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof AbstractObligationHandler) {
            return Strings.safeEquals(getObligationId(), ((AbstractObligationHandler) obj).getObligationId());
        }

        return false;
    }
}