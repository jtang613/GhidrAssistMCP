/*
 * Headless-compatible MCP server launcher.
 * Starts the Jetty MCP server without requiring the GUI plugin infrastructure.
 * Used by GhidrAssistMCPHeadlessScript to provide MCP tools in analyzeHeadless mode.
 */
package ghidrassistmcp;

import java.util.Collections;
import java.util.List;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Manages a headless MCP server instance that holds a direct program reference
 * instead of relying on GhidrAssistMCPManager's PluginTool-based program discovery.
 */
public class GhidrAssistMCPHeadlessServer {

    private static GhidrAssistMCPHeadlessServer instance;
    private static final Object lock = new Object();

    private GhidrAssistMCPServer server;
    private HeadlessBackend headlessBackend;
    private volatile boolean running = false;

    private GhidrAssistMCPHeadlessServer() {
    }

    public static GhidrAssistMCPHeadlessServer getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new GhidrAssistMCPHeadlessServer();
                }
            }
        }
        return instance;
    }

    /**
     * Start the MCP server with a direct program reference.
     *
     * @param program The current program from the headless script
     * @param host    Host to bind (typically "localhost" or "0.0.0.0")
     * @param port    Port to bind (typically 8080)
     */
    public synchronized void start(Program program, String host, int port) throws Exception {
        if (running) {
            Msg.info(this, "Headless MCP server already running, updating program");
            if (headlessBackend != null) {
                headlessBackend.setProgram(program);
            }
            return;
        }

        Msg.info(this, "Starting headless MCP server on " + host + ":" + port);

        // Create a backend wrapper that holds the program directly
        headlessBackend = new HeadlessBackend(program);

        server = new GhidrAssistMCPServer(host, port, headlessBackend);
        server.start();
        running = true;

        Msg.info(this, "Headless MCP server started successfully with " +
                headlessBackend.getAvailableTools().size() + " tools");
    }

    /**
     * Stop the MCP server.
     */
    public synchronized void stop() {
        if (!running) {
            return;
        }
        try {
            if (server != null) {
                server.stop();
            }
            Msg.info(this, "Headless MCP server stopped");
        } catch (Exception e) {
            Msg.error(this, "Error stopping headless MCP server", e);
        }
        server = null;
        headlessBackend = null;
        running = false;

        synchronized (lock) {
            instance = null;
        }
    }

    public boolean isRunning() {
        return running;
    }

    /**
     * Update the program reference (e.g., when processing a new binary).
     */
    public void setProgram(Program program) {
        if (headlessBackend != null) {
            headlessBackend.setProgram(program);
        }
    }

    /**
     * A thin wrapper around GhidrAssistMCPBackend that provides a direct program
     * reference instead of going through GhidrAssistMCPManager.
     */
    private static class HeadlessBackend extends GhidrAssistMCPBackend {

        private volatile Program currentProgram;

        HeadlessBackend(Program program) {
            super();
            this.currentProgram = program;
            // Notify backend of the initial program
            onProgramActivated(program);
        }

        void setProgram(Program program) {
            if (this.currentProgram != null) {
                onProgramDeactivated(this.currentProgram);
            }
            this.currentProgram = program;
            if (program != null) {
                onProgramActivated(program);
            }
        }

        @Override
        public Program getCurrentProgram() {
            return currentProgram;
        }

        @Override
        public List<Program> getAllOpenPrograms() {
            if (currentProgram != null) {
                return Collections.singletonList(currentProgram);
            }
            return Collections.emptyList();
        }
    }
}
