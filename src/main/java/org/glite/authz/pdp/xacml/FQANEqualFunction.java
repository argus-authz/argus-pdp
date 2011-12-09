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

package org.glite.authz.pdp.xacml;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.common.profile.AuthorizationProfileConstants;

import org.herasaf.xacml.core.function.FunctionProcessingException;
import org.herasaf.xacml.core.function.AbstractFunction;

/** Exact equality matching function for {@link FQAN}s. */
public class FQANEqualFunction extends AbstractFunction {

    /** Serial version UID. */
    private static final long serialVersionUID = 6773486599275330312L;

    /** {@inheritDoc} */
    public String getFunctionId() {
        return AuthorizationProfileConstants.ID_ALGORITHM_FQAN_EXACT_MATCH;
    }

    /** {@inheritDoc} */
    public Object handle(Object... args) throws FunctionProcessingException {
        if (args.length != 2 || !(args[0] instanceof FQAN) || !(args[1] instanceof FQAN)) {
            throw new FunctionProcessingException("This matching function only operates on two FQAN objects");
        }

        FQAN fqan1 = (FQAN) args[0];
        FQAN fqan2 = (FQAN) args[1];

        return fqan1.equals(fqan2);
    }
}