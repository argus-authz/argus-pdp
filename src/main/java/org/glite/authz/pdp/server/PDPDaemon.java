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
import java.util.ArrayList;
import java.util.Timer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.LoggingReloadTask;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyShutdownCommand;
import org.glite.authz.common.http.JettyShutdownService;
import org.glite.authz.common.util.Files;
import org.glite.authz.pdp.config.PDPConfiguration;
import org.glite.authz.pdp.config.PDPIniConfigurationParser;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.log.Log;
import org.mortbay.thread.concurrent.ThreadPool;
import org.opensaml.DefaultBootstrap;

/**
 * Main class of the PDP Daemon. This class kicks off the embedded Jetty server and shutdown service. It does not do any
 * of the request processing.
 */
public class PDPDaemon {
    
    /** System property name PDP_HOME path is bound to. */
    public static final String PDP_HOME_PROP = "org.glite.authz.pdp.home";

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
        
        ArrayList<Runnable> shutdownCommands = new ArrayList<Runnable>();

        final Timer configFileReloadTasks = new Timer(true);
        shutdownCommands.add(new Runnable() {
            public void run() {
                configFileReloadTasks.cancel();
            }
        });
        initializeLogging(System.getProperty(PDP_HOME_PROP) + "/conf/logging.xml", configFileReloadTasks);

        DefaultBootstrap.bootstrap();
        
        PDPConfiguration daemonConfig = parseConfiguration(args[0]);

        Server pepDaemonService = createDaemonService(daemonConfig);
        JettyRunThread pdpDaemonServiceThread = new JettyRunThread(pepDaemonService);
        pdpDaemonServiceThread.setName("PDP Deamon Service");
        shutdownCommands.add(new JettyShutdownCommand(pepDaemonService));
        
        if(daemonConfig.getShutdownPort() == 0){
            JettyShutdownService.startJettyShutdownService(8153, shutdownCommands);
        }else{
            JettyShutdownService.startJettyShutdownService(daemonConfig.getShutdownPort(), shutdownCommands);
        }

        Log.info("PDP service initialized");
        pdpDaemonServiceThread.start();
    }

    private static Server createDaemonService(PDPConfiguration daemonConfig) {
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

        SelectChannelConnector connector = new SelectChannelConnector();
        connector.setHost(daemonConfig.getHostname());
        if(daemonConfig.getPort() == 0){
            connector.setPort(8152);
        }else{
            connector.setPort(daemonConfig.getPort());
        }
        connector.setMaxIdleTime(daemonConfig.getConnectionTimeout());
        connector.setRequestBufferSize(daemonConfig.getReceiveBufferSize());
        connector.setResponseBufferSize(daemonConfig.getSendBufferSize());
        httpServer.setConnectors(new Connector[] { connector });

        Context servletContext = new Context(httpServer, "/", false, false);
        servletContext.setDisplayName("PDP Daemon");
        servletContext.setAttribute(PDPConfiguration.BINDING_NAME, daemonConfig);

        ServletHolder daemonRequestServlet = new ServletHolder(new AuthorizationRequestServlet());
        daemonRequestServlet.setName("PDP Daemon Servlet");
        servletContext.addServlet(daemonRequestServlet, "/authz");

        ServletHolder daemonStatusServlet = new ServletHolder(new StatusServlet());
        daemonStatusServlet.setName("PDP Status Servlet");
        servletContext.addServlet(daemonStatusServlet, "/status");

        return httpServer;
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