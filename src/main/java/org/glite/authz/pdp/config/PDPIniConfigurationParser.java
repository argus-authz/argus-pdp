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

package org.glite.authz.pdp.config;

import java.io.Reader;
import java.io.StringReader;
import java.util.List;
import java.util.StringTokenizer;

import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractIniServiceConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.pdp.obligation.IniOHConfigurationParserHelper;
import org.glite.authz.pdp.obligation.ObligationService;
import org.glite.authz.pdp.pip.IniPIPConfigurationParserHelper;
import org.glite.authz.pdp.pip.PolicyInformationPoint;
import org.glite.voms.VOMSTrustManager;
import org.ini4j.Ini;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.MandatoryAuthenticatedMessageRule;
import org.opensaml.ws.security.provider.MandatoryIssuerRule;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for PDP INI configuration files. */
@ThreadSafe
public class PDPIniConfigurationParser extends AbstractIniServiceConfigurationParser<PDPConfiguration> {

    /** The name of the {@value} INI header which contains the property for configuring the PAP interaction. */
    public static final String POLICY_SECTION_HEADER = "POLICY";

    /** The name of the {@value} property which gives the space-delimited PAP endpoint URLs. */
    public static final String PAP_PROP = "paps";

    /** The name of the {@value} property which indicates length of time, in minutes, a policy will be cached. */
    public static final String POLICY_RETENTION_PROP = "retentionInterval";

    /** The name of the {@value} property which indicates the allowed clock skew, in seconds. */
    public static final String CLOCK_SKEW_PROP = "clockSkew";

    /** The name of the {@value} property which indicates the maximum validity of messages, in seconds. */
    public static final String MESSAGE_VALIDITY_PROP = "messageValidityPeriod";

    /** Default value of the {@value AbstractIniServiceConfigurationParser#PORT_PROP} property, {@value} . */
    public static final int DEFAULT_PORT = 8152;

    /** Default value of the {@value AbstractIniServiceConfigurationParser#ADMIN_PORT_PROP} property, {@value} . */
    public static final int DEFAULT_ADMIN_PORT = 8153;

    /** Default value of the {@value #POLICY_RETENTION_PROP} property, {@value} minutes. */
    public static final int DEFAULT_POLICY_RETENTION = 240;

    /** Default value of the {@value #CLOCK_SKEW_PROP} property, {@value} seconds. */
    public static final int DEFAULT_CLOCK_SKEW = 30;

    /** Default value of the {@value #MESSAGE_VALIDITY_PROP} property, {@value} seconds. */
    public static final int DEFAULT_MESSAGE_VALIDITY = 300;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PDPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PDPConfiguration parse(Reader iniReader) throws ConfigurationException {
        return parseIni(iniReader);
    }

    /** {@inheritDoc} */
    public PDPConfiguration parse(String iniString) throws ConfigurationException {
        return parseIni(new StringReader(iniString));
    }

    /**
     * {@inheritDoc}
     * 
     * @return the port value, or the default port {@value #DEFAULT_PORT} if it is not set
     */
    protected int getPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, PORT_PROP, DEFAULT_PORT, 1, 65535);
    }

    /** 
     * {@inheritDoc}
     * 
     * @return the admin port value, or the default admin port {@value #DEFAULT_ADMIN_PORT} if it is not set
     */
    protected int getAdminPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, ADMIN_PORT_PROP, DEFAULT_ADMIN_PORT, 1, 65535);
    }

    /**
     * Parses a configuration.
     * 
     * @param iniReader INI to parse
     * 
     * @return the daemon configuration
     * 
     * @throws ConfigurationException thrown if there is a problem configuring the system
     */
    private PDPConfiguration parseIni(Reader iniReader) throws ConfigurationException {

        Ini pdpIni = new Ini();
        try {
            log.info("Loading and parsing INI configuration file");
            pdpIni.load(iniReader);
        } catch (Exception e) {
            log.error("Unable to load and parse the INI configuration file", e);
            throw new ConfigurationException("Unable to parse INI configuration file", e);
        }

        PDPConfigurationBuilder configBuilder = new PDPConfigurationBuilder();

        log.info("Processing PDP {} configuration section", SECURITY_SECTION_HEADER);
        processSecuritySection(pdpIni, configBuilder);

        log.info("Processing PDP {} configuration section", SERVICE_SECTION_HEADER);
        processServiceSection(pdpIni, configBuilder);

        Ini.Section serviceSection = pdpIni.get(SERVICE_SECTION_HEADER);

        List<PolicyInformationPoint> pips = IniPIPConfigurationParserHelper.processPolicyInformationPoints(pdpIni,
                serviceSection, configBuilder);
        log.info("Total policy information points: {}", pips.size());
        configBuilder.getPolicyInformationPoints().addAll(pips);

        ObligationService service = IniOHConfigurationParserHelper.processObligationHandlers(pdpIni, serviceSection,
                configBuilder);
        log.info("Total obligation handlers: {}", service.getObligationHandlers().size());
        configBuilder.setObligationService(service);

        log.info("Processing PDP {} configuration section", POLICY_SECTION_HEADER);
        processPAPConfiguration(pdpIni, configBuilder);

        return configBuilder.build();
    }

    /**
     * Process the PAP section of the INI file.
     * 
     * @param iniFile ini file to process
     * @param configBuilder the PDP configuration builder
     * 
     * @throws ConfigurationException thrown if there is a problem reading the INI configuration
     */
    protected void processPAPConfiguration(Ini iniFile, PDPConfigurationBuilder configBuilder)
            throws ConfigurationException {
        Ini.Section configSection = iniFile.get(POLICY_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "PDP INI configuration does not contain the rquired '" + POLICY_SECTION_HEADER
                    + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        String papsStr = IniConfigUtil.getString(configSection, PAP_PROP);
        log.info("Policy administration points: {}", papsStr);
        StringTokenizer paps = new StringTokenizer(configSection.get(PAP_PROP), " ");
        while (paps.hasMoreTokens()) {
            configBuilder.getPAPEndpoints().add(paps.nextToken());
        }

        int policyRetentionInterval = IniConfigUtil.getInt(configSection, POLICY_RETENTION_PROP,
                DEFAULT_POLICY_RETENTION, 1, Integer.MAX_VALUE);
        log.info("Policy retention interval: {} minutes", policyRetentionInterval);
        configBuilder.setPolicyRetentionInterval(policyRetentionInterval);

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(1);

        try {
            X509TrustManager trustManager = new VOMSTrustManager(configBuilder.getTrustMaterialStore());
            HttpClientBuilder soapClientBuilder = buildSOAPClientBuilder(configSection, configBuilder.getKeyManager(),
                    trustManager);
            configBuilder.setSoapClient(new HttpSOAPClient(soapClientBuilder.buildClient(), parserPool));
        } catch (Exception e) {
            throw new ConfigurationException("Unable to read X.509 trust material information.", e);
        }
    }

    /**
     * Creates the message security policy from the information in the given INI configuration section.
     * 
     * @param configSection INI section containing configuration information
     * 
     * @return the generated security policy
     */
    protected SecurityPolicy buildSecurityPolicy(Ini.Section configSection) {
        BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();

        int clockSkew = IniConfigUtil.getInt(configSection, CLOCK_SKEW_PROP, DEFAULT_CLOCK_SKEW, 1, Integer.MAX_VALUE);
        int messageValidityPeriod = IniConfigUtil.getInt(configSection, MESSAGE_VALIDITY_PROP,
                DEFAULT_MESSAGE_VALIDITY, 1, Integer.MAX_VALUE);
        log.info("SAML message validating: {} seconds with a {} second clock skew", messageValidityPeriod, clockSkew);
        IssueInstantRule issueInstant = new IssueInstantRule(clockSkew, messageValidityPeriod);
        securityPolicy.getPolicyRules().add(issueInstant);

        // TODO client cert

        // TODO xml signature

        securityPolicy.getPolicyRules().add(new MandatoryIssuerRule());

        securityPolicy.getPolicyRules().add(new MandatoryAuthenticatedMessageRule());

        return securityPolicy;
    }
}
