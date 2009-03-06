/*
 * Copyright 2008 EGEE Collaboration
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

package org.glite.authz.pdp.config;

import java.io.Reader;
import java.io.StringReader;
import java.util.StringTokenizer;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractIniConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.MandatoryAuthenticatedMessageRule;
import org.opensaml.ws.security.provider.MandatoryIssuerRule;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for PDP INI configuration files. */
@ThreadSafe
public class PDPIniConfigurationParser extends AbstractIniConfigurationParser<PDPConfiguration> {

    /** PDP INI section header. */
    public static final String SERVICE_SECTION_HEADER = "SERVICE";

    /** Property name for the PDP entityID configuration property. */
    public static final String ENTITY_ID_PROP = "entityId";

    /** Property name for the PDP hostname configuration property. */
    public static final String HOST_PROP = "host";

    /** Property name for the PDP port configuration property. */
    public static final String PORT_PROP = "port";

    /** Property name for the PDP shutdown port configuration property. */
    public static final String SD_PORT_PROP = "shutdownPort";

    /**
     * Property name for the maximum number of request that may be queued configuration property.
     */
    public static final String MAX_QUEUE_PROP = "maxRequestQueueSize";

    /** PAP INI section header. */
    public static final String POLICY_SECTION_HEADER = "POLICY";

    /** Property name for the PAP endpoints configuration property. */
    public static final String PAP_PROP = "paps";

    /** Property name for the policy retention interval configuration property. */
    public static final String POLICY_RETENTION_PROP = "retentionInternval";

    /** Property name for the clock skew. */
    public static final String CLOCK_SKEW_PROP = "clockSkew";

    /** Property name of the maximum lifetime of a message. */
    public static final String MESSAGE_VALIDITY_PROP = "messageValidityPeriod";

    /** Class logget. */
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
     * Parses a configuration.
     * 
     * @param iniReader INI to parse
     * 
     * @return the daemon configuration
     * 
     * @throws ConfigurationException thrown if there is a problem configuring the system
     */
    private PDPConfiguration parseIni(Reader iniReader) throws ConfigurationException {
        PDPConfigurationBuilder configBuilder = new PDPConfigurationBuilder();

        Ini pdpIni = new Ini();
        try {
            log.debug("Loading INI configuration file");
            pdpIni.load(iniReader);
        } catch (Exception e) {
            log.error("Unable to parser INI configuration file", e);
            throw new ConfigurationException("Unable to parse INI configuration file", e);
        }

        processPDPConfiguration(pdpIni, configBuilder);
        processPAPConfiguration(pdpIni, configBuilder);

        return configBuilder.build();
    }

    /**
     * Process the PDP section of the INI file.
     * 
     * @param iniFile ini file to process
     * @param configBuilder the PDP configuration builder
     * 
     * @throws ConfigurationException thrown if there is a problem reading the INI configuration
     */
    protected void processPDPConfiguration(Ini iniFile, PDPConfigurationBuilder configBuilder)
            throws ConfigurationException {
        Section configSection = iniFile.get(SERVICE_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "PDP INI configuration does not contain the rquired '" + SERVICE_SECTION_HEADER
                    + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        String entityId = Strings.safeTrimOrNullString(configSection.get(ENTITY_ID_PROP));
        if (entityId == null) {
            String errorMsg = "PDP INI, " + SERVICE_SECTION_HEADER + " section, does not contain a valid "
                    + ENTITY_ID_PROP + " configuration proeprty.";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }
        log.debug("PDP entity ID: {}", entityId);
        configBuilder.setEntityId(entityId);

        String host = Strings.safeTrimOrNullString(configSection.get(HOST_PROP));
        if (host == null) {
            host = "0.0.0.0";
        }
        log.debug("PDP host address: {}", host);
        configBuilder.setHost(host);

        int port = 8080;
        if (configSection.containsKey(PORT_PROP)) {
            try {
                port = Integer.parseInt(configSection.get(PORT_PROP));
            } catch (NumberFormatException e) {
                String errorMsg = configSection.get(PORT_PROP) + " is not a valid port number";
                log.error(errorMsg);
                throw new ConfigurationException(errorMsg);
            }
        }
        log.debug("PDP listening port: {}", port);
        configBuilder.setPort(port);

        int shutdownPort = 8081;
        if (configSection.containsKey(SD_PORT_PROP)) {
            try {
                shutdownPort = Integer.parseInt(configSection.get(SD_PORT_PROP));
            } catch (NumberFormatException e) {
                String errorMsg = configSection.get(SD_PORT_PROP) + " is not a valid port number";
                log.error(errorMsg);
                throw new ConfigurationException(errorMsg);
            }
        }
        log.debug("PDP shutdown port: {}", shutdownPort);
        configBuilder.setShutdownPort(shutdownPort);

        int maxConnections = 50;
        if (configSection.containsKey(MAX_REQUESTS_PROP)) {
            try {
                maxConnections = Integer.parseInt(configSection.get(MAX_REQUESTS_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(MAX_REQUESTS_PROP)
                        + " is not a valid integer, using default maximum request size of " + maxConnections);
            }
        }
        log.debug("PDP max requests: {}", maxConnections);
        configBuilder.setMaxConnections(maxConnections);

        int maxReqQueue = 50;
        if (configSection.containsKey(MAX_QUEUE_PROP)) {
            try {
                maxReqQueue = Integer.parseInt(configSection.get(MAX_QUEUE_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(MAX_QUEUE_PROP)
                        + " is not a valid integer, using default maximum require queue size of " + maxReqQueue);
            }
        }
        log.debug("PDP max request queue size: {}", maxReqQueue);
        configBuilder.setMaxRequestQueueSize(maxReqQueue);

        int receiveBuffer = 4096 * 1024;
        if (configSection.containsKey(REC_BUFF_SIZE_PROP)) {
            try {
                receiveBuffer = Integer.parseInt(configSection.get(REC_BUFF_SIZE_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(REC_BUFF_SIZE_PROP)
                        + " is not a valid integer, using default receive buffer size of " + receiveBuffer);
            }
        }
        log.debug("PDP recieve buffer size: {} bytes", receiveBuffer);
        configBuilder.setReceiveBufferSize(receiveBuffer);

        int sendBuffer = 4096 * 1024;
        if (configSection.containsKey(SEND_BUFF_SIZE_PROP)) {
            try {
                sendBuffer = Integer.parseInt(configSection.get(SEND_BUFF_SIZE_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(SEND_BUFF_SIZE_PROP)
                        + " is not a valid integer, using default send buffer size of" + sendBuffer);
            }
        }
        log.debug("PDP send buffer size: {} bytes", sendBuffer);
        configBuilder.setSendBufferSize(sendBuffer);

        configBuilder.setServiceCredential(processX509KeyInformation(configSection));

        configBuilder.setTrustManager(processX509TrustInformation(configSection));

        configBuilder.setAuthzDecisionQuerySecurityPolicy(buildSecurityPolicy(configSection));

        configBuilder.getPIPs().addAll(processPolicyInformationPoints(configSection, iniFile));
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
        Section configSection = iniFile.get(POLICY_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "PDP INI configuration does not contain the rquired '" + POLICY_SECTION_HEADER
                    + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        String papsStr = Strings.safeTrimOrNullString(configSection.get(PAP_PROP));
        if (papsStr == null) {
            String errorMsg = "PDP INI configuration, " + POLICY_SECTION_HEADER + " section, does not contain a valid "
                    + PAP_PROP + " configuration proeprty.";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }
        log.debug("Policy administration points: {}", papsStr);
        StringTokenizer paps = new StringTokenizer(configSection.get(PAP_PROP), " ");
        while (paps.hasMoreTokens()) {
            configBuilder.getPolicyAdministrationPoints().add(paps.nextToken());
        }

        int policyRetentionInterval = 4 * 60; // 4 hours, by default;
        if (configSection.containsKey(POLICY_RETENTION_PROP)) {
            try {
                policyRetentionInterval = Integer.valueOf(configSection.get(POLICY_RETENTION_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(POLICY_RETENTION_PROP)
                        + " is not a valid integer, using default policy retention interval of "
                        + policyRetentionInterval + " minutes");
            }
        }
        log.debug("Policy retention interval: {} minutes", policyRetentionInterval);
        configBuilder.setPolicyRetentionInterval(policyRetentionInterval);

        BasicParserPool parserPool = new BasicParserPool();
        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");

        int connTimeout = 30 * 1000;
        if (configSection.containsKey(CONN_TIMEOUT_PROP)) {
            connTimeout = Integer.parseInt(configSection.get(CONN_TIMEOUT_PROP));
        }
        log.debug("Policy requester connection timeout: {}ms", connTimeout);
        httpClientBuilder.setConnectionTimeout(connTimeout);

        httpClientBuilder.setMaxTotalConnections(1);
        httpClientBuilder.setMaxConnectionsPerHost(1);
        parserPool.setMaxPoolSize(1);

        int receiveBuffer = 4096 * 1024;
        if (configSection.containsKey(REC_BUFF_SIZE_PROP)) {
            try {
                receiveBuffer = Integer.parseInt(configSection.get(REC_BUFF_SIZE_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(REC_BUFF_SIZE_PROP)
                        + " is not a valid integer, using default receive buffer size of " + receiveBuffer);
            }
        }
        log.debug("Policy requester recieve buffer size: {} bytes", receiveBuffer);
        httpClientBuilder.setReceiveBufferSize(receiveBuffer);

        int sendBuffer = 4096 * 1024;
        if (configSection.containsKey(SEND_BUFF_SIZE_PROP)) {
            try {
                sendBuffer = Integer.parseInt(configSection.get(SEND_BUFF_SIZE_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(SEND_BUFF_SIZE_PROP)
                        + " is not a valid integer, using default send buffer size of" + sendBuffer);
            }
        }
        log.debug("Policy requester buffer size: {} bytes", sendBuffer);
        httpClientBuilder.setSendBufferSize(sendBuffer);

        if (configBuilder.getServiceCredential() != null || configBuilder.getTrustManager() != null) {
            TLSProtocolSocketFactory httpsSocketFactory = new TLSProtocolSocketFactory(configBuilder
                    .getServiceCredential(), configBuilder.getTrustManager());
            httpClientBuilder.setHttpsProtocolSocketFactory(httpsSocketFactory);
        }

        configBuilder.setSoapClient(new HttpSOAPClient(httpClientBuilder.buildClient(), parserPool));
    }

    /**
     * Creates the message security policy from the information in the given INI configuration section.
     * 
     * @param configSection INI section containing configuration information
     * 
     * @return the generated security policy
     */
    protected SecurityPolicy buildSecurityPolicy(Section configSection) {
        BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();

        int clockSkew = 30;
        if (configSection.containsKey(CLOCK_SKEW_PROP)) {
            try {
                clockSkew = Integer.parseInt(configSection.get(CLOCK_SKEW_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(CLOCK_SKEW_PROP) + " is not a valid integer, using default clock skew of "
                        + clockSkew);
            }
        }

        int messageValidityPeriod = 300;
        if (configSection.containsKey(MESSAGE_VALIDITY_PROP)) {
            try {
                messageValidityPeriod = Integer.parseInt(configSection.get(MESSAGE_VALIDITY_PROP));
            } catch (NumberFormatException e) {
                log.error(configSection.get(MESSAGE_VALIDITY_PROP)
                        + " is not a valid integer, using default message validity period of " + messageValidityPeriod);
            }
        }

        log.debug("SAML message validating: {} seconds with a {} second clock skew", messageValidityPeriod, clockSkew);
        IssueInstantRule issueInstant = new IssueInstantRule(clockSkew, messageValidityPeriod);
        securityPolicy.getPolicyRules().add(issueInstant);

        // TODO client cert

        // TODO xml signature

        securityPolicy.getPolicyRules().add(new MandatoryIssuerRule());

        securityPolicy.getPolicyRules().add(new MandatoryAuthenticatedMessageRule());

        return securityPolicy;
    }
}