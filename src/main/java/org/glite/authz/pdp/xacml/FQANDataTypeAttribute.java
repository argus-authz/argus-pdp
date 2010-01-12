/*
 * Copyright 2010 Members of the EGEE Collaboration.
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
package org.glite.authz.pdp.xacml;

import java.text.ParseException;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.common.profile.WorkerNodeProfileV1Constants;
import org.herasaf.xacml.SyntaxException;
import org.herasaf.xacml.core.dataTypeAttribute.impl.AbstractDataTypeAttribute;

/** XACML data type FQAN converter. */
public class FQANDataTypeAttribute extends AbstractDataTypeAttribute<FQAN> {

    /** Serial version UID. */
    private static final long serialVersionUID = 3941820813565815821L;

    /** {@inheritDoc} */
    public String getDatatypeURI() {
        return WorkerNodeProfileV1Constants.DAT_FQAN;
    }
    
    /** {@inheritDoc} */
    public FQAN convertTo(String jaxbRepresentation) throws SyntaxException {
        try{
            return FQAN.parseFQAN(jaxbRepresentation);
        }catch(ParseException e){
            throw new SyntaxException(e.getMessage());
        }
    }
}