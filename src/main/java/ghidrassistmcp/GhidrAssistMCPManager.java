/*
 * Singleton manager for GhidrAssistMCP that coordinates multiple CodeBrowser windows.
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Singleton manager that coordinates the MCP server across multiple CodeBrowser windows.
 *
 * This solves the problem of multiple plugin instances each trying to start their own
 * MCP server. Instead, we have:
 * - One shared MCP backend that tracks ALL open programs across ALL tools
 * - One shared MCP server (on port 8080) that serves all requests
 * - Multiple plugin instances that register/unregister their tools
 */
public class GhidrAssistMCPManager {

    private static GhidrAssistMCPManager instance;
    private static final Object lock = new Object();

    private final GhidrAssistMCPBackend backend;
    private GhidrAssistMCPServer server;
    private GhidrAssistMCPProvider provider;

    // Track all registered plugin tools
    private final List<PluginTool> registeredTools = new CopyOnWriteArrayList<>();

    // Track the most recently active tool (for context awareness)
    private volatile PluginTool activeTool;

    // Track the most recently active plugin instance (for UI context)
    private volatile GhidrAssistMCPPlugin activePlugin;

    // Server configuration
    private String currentHost = "localhost";
    private int currentPort = 8080;
    private boolean serverEnabled = true;

    /**
     * Private constructor for singleton pattern.
     */
    private GhidrAssistMCPManager() {
        Msg.info(this, "Initializing GhidrAssistMCP Manager (singleton)");
        backend = new GhidrAssistMCPBackend();
        backend.setManager(this);
    }

    /**
     * Get the singleton instance of the manager.
     */
    public static GhidrAssistMCPManager getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new GhidrAssistMCPManager();
                }
            }
        }
        return instance;
    }

    /**
     * Register a plugin's tool with the manager.
     * The first tool to register will start the MCP server.
     *
     * @param tool The PluginTool to register
     * @param pluginProvider The UI provider (only used from first registration)
     * @return true if this is the first registration (server owner)
     */
    public synchronized boolean registerTool(PluginTool tool, GhidrAssistMCPProvider pluginProvider) {
        if (tool == null) {
            Msg.warn(this, "Attempted to register null tool");
            return false;
        }

        if (registeredTools.contains(tool)) {
            Msg.info(this, "Tool already registered: " + tool.getName());
            return false;
        }

        registeredTools.add(tool);
        Msg.info(this, "Registered tool: " + tool.getName() + " (total: " + registeredTools.size() + ")");

        // First registration starts the server
        if (registeredTools.size() == 1) {
            this.provider = pluginProvider;
            if (provider != null) {
                backend.addEventListener(provider);
                provider.onBackendReady();
            }
            startServer();
            return true;
        }

        // Notify about new tool registration
        if (provider != null) {
            provider.logSession("New CodeBrowser registered: " + tool.getName());
        }

        return false;
    }

    /**
     * Unregister a plugin's tool from the manager.
     * When all tools are unregistered, the server is stopped.
     *
     * @param tool The PluginTool to unregister
     */
    public synchronized void unregisterTool(PluginTool tool) {
        if (tool == null) {
            return;
        }

        boolean removed = registeredTools.remove(tool);
        if (removed) {
            Msg.info(this, "Unregistered tool: " + tool.getName() + " (remaining: " + registeredTools.size() + ")");

            if (provider != null) {
                provider.logSession("CodeBrowser unregistered: " + tool.getName());
            }
        }

        // Stop server when all tools are unregistered
        if (registeredTools.isEmpty()) {
            Msg.info(this, "All tools unregistered, stopping server");
            stopServer();

            // Clean up singleton for potential restart
            synchronized (lock) {
                if (provider != null) {
                    backend.removeEventListener(provider);
                    provider = null;
                }
                instance = null;
            }
        }
    }

    /**
     * Get all programs from all registered tools.
     * This is the key method that enables multi-window support.
     */
    public List<Program> getAllOpenPrograms() {
        List<Program> allPrograms = new ArrayList<>();

        for (PluginTool tool : registeredTools) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) {
                Program[] programs = pm.getAllOpenPrograms();
                if (programs != null) {
                    for (Program p : programs) {
                        if (!allPrograms.contains(p)) {
                            allPrograms.add(p);
                        }
                    }
                }
            }
        }

        return allPrograms;
    }

    /**
     * Set the active tool (called when a CodeBrowser window gains focus).
     * This helps determine which program context to use for incoming requests.
     */
    public synchronized void setActiveTool(PluginTool tool) {
        if (registeredTools.contains(tool)) {
            activeTool = tool;
            Msg.info(this, "Active tool changed: " + tool.getName());

            if (provider != null) {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm != null) {
                    Program current = pm.getCurrentProgram();
                    if (current != null) {
                        provider.logSession("Active context: " + current.getName() + " (from " + tool.getName() + ")");
                    }
                }
            }
        }
    }

    /**
     * Get the currently active tool (most recently focused CodeBrowser).
     */
    public PluginTool getActiveTool() {
        return activeTool;
    }

    /**
     * Set the active plugin instance (called when a plugin gains focus).
     * This provides access to UI context like current address and function.
     */
    public synchronized void setActivePlugin(GhidrAssistMCPPlugin plugin) {
        this.activePlugin = plugin;
    }

    /**
     * Get the currently active plugin instance (for UI context access).
     */
    public GhidrAssistMCPPlugin getActivePlugin() {
        return activePlugin;
    }

    /**
     * Get the currently active program across all tools.
     * Prioritizes the program from the most recently focused tool.
     */
    public Program getCurrentProgram() {
        // First, try the active tool if one is set
        if (activeTool != null) {
            ProgramManager pm = activeTool.getService(ProgramManager.class);
            if (pm != null) {
                Program current = pm.getCurrentProgram();
                if (current != null) {
                    return current;
                }
            }
        }

        // Fall back to any tool's current program
        for (PluginTool tool : registeredTools) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) {
                Program current = pm.getCurrentProgram();
                if (current != null) {
                    return current;
                }
            }
        }
        return null;
    }

    /**
     * Find a program by name across all registered tools.
     */
    public Program getProgramByName(String programName) {
        if (programName == null || programName.trim().isEmpty()) {
            return getCurrentProgram();
        }

        List<Program> programs = getAllOpenPrograms();

        // Exact match
        for (Program p : programs) {
            if (p.getName().equals(programName)) {
                return p;
            }
        }

        // Case-insensitive match
        for (Program p : programs) {
            if (p.getName().equalsIgnoreCase(programName)) {
                return p;
            }
        }

        // Partial match
        for (Program p : programs) {
            if (p.getName().toLowerCase().contains(programName.toLowerCase())) {
                return p;
            }
        }

        return null;
    }

    /**
     * Get the shared backend instance.
     */
    public GhidrAssistMCPBackend getBackend() {
        return backend;
    }

    /**
     * Get the UI provider (if available).
     */
    public GhidrAssistMCPProvider getProvider() {
        return provider;
    }

    /**
     * Get the number of registered tools.
     */
    public int getRegisteredToolCount() {
        return registeredTools.size();
    }

    /**
     * Check if the server is running.
     */
    public boolean isServerRunning() {
        return server != null;
    }

    /**
     * Apply configuration changes.
     */
    public void applyConfiguration(String host, int port, boolean enabled,
                                   java.util.Map<String, Boolean> toolStates) {
        if (provider != null) {
            provider.logMessage("Applying configuration: " + host + ":" + port + " enabled=" + enabled);
        }

        boolean needsRestart = false;

        if (!host.equals(currentHost) || port != currentPort) {
            currentHost = host;
            currentPort = port;
            needsRestart = true;
        }

        if (enabled != serverEnabled) {
            serverEnabled = enabled;
            needsRestart = true;
        }

        // Update tool states
        if (backend != null && toolStates != null) {
            backend.updateToolEnabledStates(toolStates);
        }

        if (needsRestart) {
            stopServer();
            if (serverEnabled) {
                startServer();
            }
        }

        if (provider != null) {
            provider.refreshToolsList();
        }
    }

    /**
     * Get current configuration.
     */
    public String getCurrentHost() {
        return currentHost;
    }

    public int getCurrentPort() {
        return currentPort;
    }

    public boolean isServerEnabled() {
        return serverEnabled;
    }

    /**
     * Start the MCP server.
     */
    private void startServer() {
        if (!serverEnabled) {
            if (provider != null) {
                provider.logSession("Server disabled - not starting");
            }
            return;
        }

        if (server != null) {
            Msg.info(this, "Server already running");
            return;
        }

        try {
            server = new GhidrAssistMCPServer(currentPort, backend, provider);
            server.start();
            if (provider != null) {
                provider.logSession("Server started on " + currentHost + ":" + currentPort);
            }
            Msg.info(this, "MCP Server started on port " + currentPort);
        } catch (Exception e) {
            if (provider != null) {
                provider.logSession("Failed to start server: " + e.getMessage());
            }
            Msg.error(this, "Failed to start MCP Server", e);
            server = null;
        }
    }

    /**
     * Stop the MCP server.
     */
    private void stopServer() {
        if (server != null) {
            try {
                server.stop();
                if (provider != null) {
                    provider.logSession("Server stopped");
                }
                Msg.info(this, "MCP Server stopped");
            } catch (Exception e) {
                if (provider != null) {
                    provider.logSession("Error stopping server: " + e.getMessage());
                }
                Msg.error(this, "Failed to stop MCP Server", e);
            }
            server = null;
        }
    }
}
