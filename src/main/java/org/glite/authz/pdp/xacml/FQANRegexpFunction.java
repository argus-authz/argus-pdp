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

import java.text.ParseException;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.common.profile.WorkerNodeProfileV1Constants;
import org.herasaf.xacml.core.function.FunctionProcessingException;
import org.herasaf.xacml.core.function.impl.AbstractFunction;

/** Regular expression FQAN matching function. */
public class FQANRegexpFunction extends AbstractFunction {

    /** Serial version UID. */
    private static final long serialVersionUID = 678277241574383213L;

    /** {@inheritDoc} */
    public String getFunctionId() {
        return WorkerNodeProfileV1Constants.ALG_FQAN_REGEXP;
    }

    /** {@inheritDoc} */
    public Object handle(Object... args) throws FunctionProcessingException {
        if (args.length != 2 || !(args[0] instanceof String) || !(args[1] instanceof FQAN)) {
            throw new FunctionProcessingException(
                    "This matching function only operates on an FQAN regular expression string and a FQAN object");
        }

        String regexp = (String) args[0];
        FQAN fqan = (FQAN) args[1];

        try {
            return fqan.matches(regexp);
        } catch (ParseException e) {
            throw new FunctionProcessingException("Invalid FQAN regular expression");
        }
    }
}