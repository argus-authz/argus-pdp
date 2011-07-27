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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.http.JettyAdminService;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyShutdownTask;
import org.glite.authz.common.http.JettySslSelectChannelConnector;
import org.glite.authz.common.http.StatusCommand;
import org.glite.authz.common.http.TimerShutdownTask;
import org.glite.authz.common.logging.AccessLoggingFilter;
import org.glite.authz.common.logging.LoggingReloadTask;
import org.glite.authz.common.util.Files;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.config.PDPIniConfigurationParser;
import org.glite.authz.pdp.pip.PolicyInformationPoint;
import org.glite.authz.pdp.policy.PolicyRepository;
import org.glite.authz.pdp.util.SAMLUtil;
import org.glite.authz.pdp.util.XACMLUtil;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.FilterHolder;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.thread.concurrent.ThreadPool;
import org.opensaml.DefaultBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main class of the PDP Daemon. This class kicks off the embedded Jetty server
 * and shutdown service. It does not do any of the request processing.
 */
public final class PDPDaemon {

    /** System property name PDP_HOME path is bound to. */
    public static final String PDP_HOME_PROP= "org.glite.authz.pdp.home";

    /** System property name PDP_CONFDIR path is bound to. */
    public static final String PDP_CONFDIR_PROP= "org.glite.authz.pdp.confdir";

    /** System property name PDP_LOGDIR path is bound to. */
    public static final String PDP_LOGDIR_PROP= "org.glite.authz.pdp.logdir";

    /** Default admin port: {@value} */
    public static int DEFAULT_ADMIN_PORT= 8153;

    /** Default admin host: {@value} */
    public static String DEFAULT_ADMIN_HOST= "localhost";

    /** Default service port: {@value} */
    public static int DEFAULT_SERVICE_PORT= 8152;

    /** Default logging configuration refresh period: {@value} ms */
    public static final int DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD= 5 * 60 * 1000;

    /** Class logger. */
    private static final Logger LOG= LoggerFactory.getLogger(PDPDaemon.class);

    /** Constructor. */
    private PDPDaemon() {
    }

    /**
     * Entry point for starting the daemon.
     * 
     * @param args
     *            command line arguments
     * 
     * @throws Exception
     *             thrown if there is a problem starting the daemon
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 1) {
            errorAndExit("Missing configuration file argument", null);
        }

        String confDir= System.getProperty(PDP_CONFDIR_PROP);
        if (confDir == null) {
            errorAndExit("System property " + PDP_CONFDIR_PROP + " is not set",
                         null);
        }

        final Timer backgroundTaskTimer= new Timer(true);

        String loggingConfigFilePath= confDir + "/logging.xml";
        initializeLogging(loggingConfigFilePath, backgroundTaskTimer);

        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
        HerasAFBootstrap.bootstap();
        
        // speed optimization
        SAMLUtil.bootstrap();
        XACMLUtil.bootstrap();

        PDPConfiguration daemonConfig= parseConfiguration(args[0]);
        PolicyRepository policyRepository= PolicyRepository.instance(daemonConfig,
                                                                     backgroundTaskTimer);

        List<PolicyInformationPoint> pips= daemonConfig.getPolicyInformationPoints();
        if (pips != null && !pips.isEmpty()) {
            for (PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()) {
                if (pip != null) {
                    LOG.debug("Starting PIP {}", pip.getId());
                    pip.start();
                }
            }
        }

        Server authzService= createDaemonService(daemonConfig,
                                                 backgroundTaskTimer);
        JettyRunThread pdpDaemonServiceThread= new JettyRunThread(authzService);
        pdpDaemonServiceThread.setName("PDP Service");
        pdpDaemonServiceThread.start();

        JettyAdminService adminService= createAdminService(daemonConfig,
                                                           backgroundTaskTimer,
                                                           policyRepository,
                                                           authzService);
        adminService.start();

        LOG.info(Version.getServiceIdentifier() + " started");
    }

    /**
     * Creates the PDP daemon server.
     * 
     * @param daemonConfig
     *            daemon configuration
     * @param taskTimer
     *            task timer used to schedule various background tasks
     * 
     * @return the unstarted PDP daemon server
     */
    private static Server createDaemonService(PDPConfiguration daemonConfig,
            Timer taskTimer) {
        Server httpServer= new Server();
        httpServer.setSendServerVersion(false);
        httpServer.setSendDateHeader(false);
        httpServer.setGracefulShutdown(5000);

        BlockingQueue<Runnable> requestQueue;
        if (daemonConfig.getMaxRequestQueueSize() < 1) {
            requestQueue= new LinkedBlockingQueue<Runnable>();
        }
        else {
            requestQueue= new ArrayBlockingQueue<Runnable>(daemonConfig.getMaxRequestQueueSize());
        }
        ThreadPool threadPool= new ThreadPool(5,
                                              daemonConfig.getMaxRequests(),
                                              1,
                                              TimeUnit.SECONDS,
                                              requestQueue);
        httpServer.setThreadPool(threadPool);

        Connector connector= createServiceConnector(daemonConfig);
        httpServer.setConnectors(new Connector[] { connector });

        Context servletContext= new Context(httpServer, "/", false, false);
        servletContext.setDisplayName("PDP Daemon");
        servletContext.setAttribute(PDPConfiguration.BINDING_NAME, daemonConfig);
        servletContext.setAttribute(AuthorizationRequestServlet.TIMER_ATTRIB,
                                    taskTimer);

        FilterHolder accessLoggingFilter= new FilterHolder(new AccessLoggingFilter());
        servletContext.addFilter(accessLoggingFilter, "/*", Context.REQUEST);

        ServletHolder daemonRequestServlet= new ServletHolder(new AuthorizationRequestServlet());
        daemonRequestServlet.setName("PDP Servlet");
        servletContext.addServlet(daemonRequestServlet, "/authz");

        return httpServer;
    }

    /**
     * Builds an admin service for the PDP. This admin service has the following
     * commands registered with it:
     * 
     * <ul>
     * <li><em>shutdown</em> - shuts down the PDP daemon service and the admin
     * service</li>
     * <li><em>status</em> - prints out a status page w/ metrics</li>
     * <li><em>reloadPolicy</em> - reloads the PDP policy</li>
     * </ul>
     * 
     * @param daemonConfig
     *            PDP configuration
     * @param backgroundTaskTimer
     *            timer used for background tasks
     * @param policyRepository
     *            PDP policy repository
     * @param daemonService
     *            the PDP daemon service
     * 
     * @return the admin service
     */
    private static JettyAdminService createAdminService(
            PDPConfiguration daemonConfig, Timer backgroundTaskTimer,
            PolicyRepository policyRepository, Server daemonService) {

        String adminHost= daemonConfig.getAdminHost();
        if (adminHost == null) {
            adminHost= DEFAULT_ADMIN_HOST;
        }

        int adminPort= daemonConfig.getAdminPort();
        if (adminPort < 1) {
            adminPort= DEFAULT_ADMIN_PORT;
        }

        JettyAdminService adminService= new JettyAdminService(adminHost,
                                                              adminPort,
                                                              daemonConfig.getAdminPassword());

        adminService.registerAdminCommand(new StatusCommand(daemonConfig.getServiceMetrics()));
        adminService.registerAdminCommand(new ReloadPolicyCommand(policyRepository));

        adminService.registerShutdownTask(new TimerShutdownTask(backgroundTaskTimer));
        adminService.registerShutdownTask(new JettyShutdownTask(daemonService));

        return adminService;
    }

    /**
     * Creates the HTTP connector used to receive authorization requests.
     * 
     * @param daemonConfig
     *            the daemon configuration
     * 
     * @return the created connector
     */
    private static Connector createServiceConnector(
            PDPConfiguration daemonConfig) {
        Connector connector;
        if (!daemonConfig.isSslEnabled()) {
            connector= new SelectChannelConnector();
        }
        else {
            if (daemonConfig.getKeyManager() == null) {
                LOG.error("Service port was meant to be SSL enabled but no service key/certificate was specified in the configuration file");
            }
            if (daemonConfig.getTrustManager() == null) {
                LOG.error("Service port was meant to be SSL enabled but no trust information directory was specified in the configuration file");
            }
            connector= new JettySslSelectChannelConnector(daemonConfig.getKeyManager(),
                                                          daemonConfig.getTrustManager());
        }
        connector.setHost(daemonConfig.getHostname());
        if (daemonConfig.getPort() == 0) {
            connector.setPort(DEFAULT_SERVICE_PORT);
        }
        else {
            connector.setPort(daemonConfig.getPort());
        }
        connector.setMaxIdleTime(daemonConfig.getConnectionTimeout());
        connector.setRequestBufferSize(daemonConfig.getReceiveBufferSize());
        connector.setResponseBufferSize(daemonConfig.getSendBufferSize());

        return connector;
    }

    /**
     * Reads the configuration file and creates a configuration from it.
     * 
     * @param configFilePath
     *            path to configuration file
     * 
     * @return configuration file and creates a configuration from it
     */
    private static PDPConfiguration parseConfiguration(String configFilePath) {
        File configFile= null;

        try {
            configFile= Files.getReadableFile(configFilePath);
        } catch (IOException e) {
            errorAndExit(e.getMessage(), null);
        }

        try {
            PDPIniConfigurationParser configParser= new PDPIniConfigurationParser();
            return configParser.parse(new FileReader(configFile));
        } catch (IOException e) {
            errorAndExit("Unable to read configuration file " + configFilePath,
                         e);
        } catch (ConfigurationException e) {
            errorAndExit("Error parsing configuration file " + configFilePath,
                         e);
        }
        return null;
    }

    /**
     * Logs, as an error, the error message and exits the program.
     * 
     * @param errorMessage
     *            error message
     * @param e
     *            exception that caused it
     */
    private static void errorAndExit(String errorMessage, Exception e) {
        System.err.println(errorMessage);
        if (e != null) {
            System.err.println("This error was caused by the exception:");
            e.printStackTrace(System.err);
        }

        System.out.flush();
        System.exit(1);
    }

    /**
     * Initializes the logging system and starts the process to watch for config
     * file changes.
     * <p>
     * The function uses {@link #errorAndExit(String, Exception)} if the
     * loggingConfigFilePath is a directory, does not exist, or can not be read
     * 
     * 
     * @param loggingConfigFilePath
     *            path to the logging configuration file
     * @param reloadTasks
     *            timer controlling the reloading of tasks
     */
    private static void initializeLogging(String loggingConfigFilePath,
            Timer reloadTasks) {
        LoggingReloadTask reloadTask= null;
        try {
            reloadTask= new LoggingReloadTask(loggingConfigFilePath);
        } catch (IOException e) {
            errorAndExit("Invalid logging configuration file: "
                    + loggingConfigFilePath, e);
        }
        // check/reload every 5 minutes
        int refreshPeriod= DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD;
        reloadTask.run();
        reloadTasks.scheduleAtFixedRate(reloadTask,
                                        refreshPeriod,
                                        refreshPeriod);
    }
}
