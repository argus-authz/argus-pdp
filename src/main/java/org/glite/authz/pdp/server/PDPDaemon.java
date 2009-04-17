/*
 * Copyright 2009 EGEE Collaboration
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

package org.glite.authz.pdp.server;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Timer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyShutdownCommand;
import org.glite.authz.common.http.JettyShutdownService;
import org.glite.authz.common.http.JettySslSelectChannelConnector;
import org.glite.authz.common.http.ServiceStatusServlet;
import org.glite.authz.common.logging.AccessLoggingFilter;
import org.glite.authz.common.logging.LoggingReloadTask;
import org.glite.authz.common.util.Files;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.config.PDPIniConfigurationParser;
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
 * Main class of the PDP Daemon. This class kicks off the embedded Jetty server and shutdown service. It does not do any
 * of the request processing.
 */
public class PDPDaemon {

    /** System property name PDP_HOME path is bound to. */
    public static final String PDP_HOME_PROP = "org.glite.authz.pdp.home";

    /** Class logger. */
    private final static Logger log = LoggerFactory.getLogger(PDPDaemon.class);

    /** Constructor. */
    private PDPDaemon() {
    }

    /**
     * Entry point for starting the daemon.
     * 
     * @param args command line arguments
     * 
     * @throws Exception thrown if there is a problem starting the daemon
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 1) {
            errorAndExit("Invalid configuration file", null);
        }
        
        Security.addProvider(new BouncyCastleProvider());

        ArrayList<Runnable> shutdownCommands = new ArrayList<Runnable>();

        final Timer taskTimer = new Timer(true);
        shutdownCommands.add(new Runnable() {
            public void run() {
                taskTimer.cancel();
            }
        });
        initializeLogging(System.getProperty(PDP_HOME_PROP) + "/conf/logging.xml", taskTimer);

        DefaultBootstrap.bootstrap();
        HerasAFBootstrap.bootstap();

        PDPConfiguration daemonConfig = parseConfiguration(args[0]);

        Server pepDaemonService = createDaemonService(daemonConfig, taskTimer);
        JettyRunThread pdpDaemonServiceThread = new JettyRunThread(pepDaemonService);
        pdpDaemonServiceThread.setName("PDP Deamon Service");
        shutdownCommands.add(new JettyShutdownCommand(pepDaemonService));

        if (daemonConfig.getShutdownPort() == 0) {
            JettyShutdownService.startJettyShutdownService(8153, shutdownCommands);
        } else {
            JettyShutdownService.startJettyShutdownService(daemonConfig.getShutdownPort(), shutdownCommands);
        }

        pdpDaemonServiceThread.start();
        log.info(Version.getServiceIdentifier() + " started");
    }

    private static Server createDaemonService(PDPConfiguration daemonConfig, Timer taskTimer) {
        Server httpServer = new Server();
        httpServer.setSendServerVersion(false);
        httpServer.setSendDateHeader(false);

        BlockingQueue<Runnable> requestQueue;
        if (daemonConfig.getMaxRequestQueueSize() < 1) {
            requestQueue = new LinkedBlockingQueue<Runnable>();
        } else {
            requestQueue = new ArrayBlockingQueue<Runnable>(daemonConfig.getMaxRequestQueueSize());
        }
        ThreadPool threadPool = new ThreadPool(5, daemonConfig.getMaxRequests(), 1, TimeUnit.SECONDS, requestQueue);
        httpServer.setThreadPool(threadPool);

        Connector connector = createServiceConnector(daemonConfig);
        httpServer.setConnectors(new Connector[] { connector });

        Context servletContext = new Context(httpServer, "/", false, false);
        servletContext.setDisplayName("PDP Daemon");
        servletContext.setAttribute(PDPConfiguration.BINDING_NAME, daemonConfig);
        servletContext.setAttribute(AuthorizationRequestServlet.TIMER_ATTRIB, taskTimer);

        FilterHolder accessLoggingFilter = new FilterHolder(new AccessLoggingFilter());
        servletContext.addFilter(accessLoggingFilter, "/*", Context.REQUEST);

        ServletHolder daemonRequestServlet = new ServletHolder(new AuthorizationRequestServlet());
        daemonRequestServlet.setName("PDP Daemon Servlet");
        servletContext.addServlet(daemonRequestServlet, "/authz");

        ServletHolder daemonStatusServlet = new ServletHolder(new ServiceStatusServlet());
        daemonStatusServlet.setName("PDP Status Servlet");
        servletContext.addServlet(daemonStatusServlet, "/status");

        return httpServer;
    }
    
    /**
     * Creates the HTTP connector used to receive authorization requests.
     * 
     * @param daemonConfig the daemon configuration
     * 
     * @return the created connector
     */
    private static Connector createServiceConnector(PDPConfiguration daemonConfig){
        Connector connector;
        if(!daemonConfig.isSslEnabled()){
            connector = new SelectChannelConnector();
        }else{
            if(daemonConfig.getKeyManager() == null){
                log.error("Service port was meant to be SSL enabled but no service key/certificate was specified in the configuration file");
            }
            if(daemonConfig.getTrustManager() == null){
                log.error("Service port was meant to be SSL enabled but no trust information directory was specified in the configuration file");
            }
            connector = new JettySslSelectChannelConnector(daemonConfig.getKeyManager(), daemonConfig.getTrustManager());
        }
        connector.setHost(daemonConfig.getHostname());
        if (daemonConfig.getPort() == 0) {
            connector.setPort(8152);
        } else {
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
     * @param configFilePath path to configuration file
     * 
     * @return configuration file and creates a configuration from it
     */
    private static PDPConfiguration parseConfiguration(String configFilePath) {
        File configFile = null;

        try {
            configFile = Files.getReadableFile(configFilePath);
        } catch (IOException e) {
            errorAndExit(e.getMessage(), null);
        }

        try {
            PDPIniConfigurationParser configParser = new PDPIniConfigurationParser();
            return configParser.parse(new FileReader(configFile));
        } catch (IOException e) {
            errorAndExit("Unable to read configuration file " + configFilePath, e);
        } catch (ConfigurationException e) {
            errorAndExit("Error parsing configuration file " + configFilePath, e);
        }
        return null;
    }

    /**
     * Logs, as an error, the error message and exits the program.
     * 
     * @param errorMessage error message
     * @param e exception that caused it
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
     * Initializes the logging system and starts the process to watch for config file changes.
     * 
     * @param loggingConfigFilePath path to the logging configuration file
     * @param reloadTasks timer controlling the reloading of tasks
     */
    private static void initializeLogging(String loggingConfigFilePath, Timer reloadTasks) {
        LoggingReloadTask reloadTask = new LoggingReloadTask(loggingConfigFilePath);
        int refreshPeriod = 5 * 60 * 1000; // check/reload every 5 minutes
        reloadTask.run();
        reloadTasks.scheduleAtFixedRate(reloadTask, refreshPeriod, refreshPeriod);
    }
}