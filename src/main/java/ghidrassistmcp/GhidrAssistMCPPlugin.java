/* 
 * 
 */
package ghidrassistmcp;

import java.util.Map;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

/**
 * GhidrAssistMCP Plugin - Provides an MCP (Model Context Protocol) server for Ghidra analysis capabilities.
 * Features a configurable UI with tool management and request logging.
 */
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MCP Server for Ghidra",
	description = "Provides a configurable MCP (Model Context Protocol) server for Ghidra analysis capabilities with tool management and logging."
)
public class GhidrAssistMCPPlugin extends ProgramPlugin {

	private GhidrAssistMCPProvider provider;
	private GhidrAssistMCPServer mcpServer;
	private GhidrAssistMCPBackend backend;
	
	// Current configuration
	private String currentHost = "localhost";
	private int currentPort = 8080;
	private boolean serverEnabled = true;
	
	// Current UI location tracking
	private volatile ProgramLocation currentLocation1;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidrAssistMCPPlugin(PluginTool tool) {
		super(tool);
		
		// Create the UI provider but don't register it yet
		provider = new GhidrAssistMCPProvider(tool, this);
	}

	@Override
	public void init() {
		super.init();

		// Initialize MCP Backend first
		backend = new GhidrAssistMCPBackend();
		
		// Set plugin reference for UI-aware tools
		backend.setPlugin(this);
		
		// Register provider as event listener regardless of UI registration success
		// This ensures logging works even if UI fails to register
		if (provider != null) {
			backend.addEventListener(provider);
			provider.onBackendReady();
			Msg.info(this, "Provider registered as event listener");
		} else {
			Msg.warn(this, "Provider is null - event listener not registered");
		}

		// Register the UI provider with the tool (separate from event listening)
		if (provider != null) {
			try {
				tool.addComponentProvider(provider, true);
				Msg.info(this, "Successfully registered UI provider");
			} catch (IllegalArgumentException e) {
				if (e.getMessage() != null && e.getMessage().contains("was already added")) {
					Msg.info(this, "UI provider already registered, continuing");
				} else {
					Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
					// Don't set provider to null - keep it for event listening
				}
			} catch (Exception e) {
				Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
				// Don't set provider to null - keep it for event listening
			}
		}
		
		// Start server with initial configuration
		startServer();
		
		if (provider != null) {
			provider.logSession("Plugin initialized");
		}
	}
	
	/**
	 * Apply new configuration from the UI.
	 */
	public void applyConfiguration(String host, int port, boolean enabled, Map<String, Boolean> toolStates) {
		if (provider != null) {
			provider.logMessage("Applying configuration: " + host + ":" + port + " enabled=" + enabled);
		}
		
		boolean needsRestart = false;
		
		// Check if server settings changed
		if (!host.equals(currentHost) || port != currentPort) {
			currentHost = host;
			currentPort = port;
			needsRestart = true;
		}
		
		// Check if server enabled state changed
		if (enabled != serverEnabled) {
			serverEnabled = enabled;
			needsRestart = true;
		}
		
		// Update tool enabled states
		updateToolStates(toolStates);
		
		// Restart server if needed
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
	
	private void updateToolStates(Map<String, Boolean> toolStates) {
		if (backend != null) {
			// Update backend with new tool states
			backend.updateToolEnabledStates(toolStates);
			
			if (provider != null) {
				provider.logMessage("Updated tool states for " + toolStates.size() + " tools");
			}
		}
	}
	
	private void startServer() {
		if (!serverEnabled) {
			if (provider != null) {
				provider.logSession("Server disabled - not starting");
			}
			return;
		}
		
		try {
			mcpServer = new GhidrAssistMCPServer(currentPort, backend, provider);
			mcpServer.start();
			if (provider != null) {
				provider.logSession("Server started on " + currentHost + ":" + currentPort);
			}
			Msg.info(this, "MCP Server started on port " + currentPort);
		} catch (Exception e) {
			if (provider != null) {
				provider.logSession("Failed to start server: " + e.getMessage());
			}
			Msg.error(this, "Failed to start MCP Server", e);
		}
	}
	
	private void stopServer() {
		if (mcpServer != null) {
			try {
				mcpServer.stop();
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
			mcpServer = null;
		}
	}
	
	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		if (backend != null) {
			backend.onProgramActivated(program);
			if (provider != null) {
				provider.logSession("Program activated: " + program.getName());
			}
		}
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		this.currentLocation1 = loc;
		if (provider != null && loc != null) {
			provider.logMessage("Location changed to: " + loc.getAddress());
		}
	}
	
	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		if (backend != null) {
			backend.onProgramDeactivated(program);
			if (provider != null) {
				provider.logSession("Program deactivated: " + (program != null ? program.getName() : "null"));
			}
		}
	}
	
	@Override
	protected void dispose() {
		if (provider != null) {
			provider.logSession("Plugin disposing");
			
			// Remove provider as event listener
			if (backend != null) {
				backend.removeEventListener(provider);
			}
			
			try {
				tool.removeComponentProvider(provider);
			} catch (Exception e) {
				Msg.error(this, "Error removing UI provider", e);
			}
			provider = null;
		}
		stopServer();
		super.dispose();
	}
	
	/**
	 * Get the MCP backend for tool management.
	 */
	public GhidrAssistMCPBackend getBackend() {
		return backend;
	}
	
	/**
	 * Get the current server configuration.
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
	 * Get the current program.
	 */
	public Program getCurrentProgram() {
		return super.getCurrentProgram();
	}
	
	/**
	 * Get the current UI address from the location tracker.
	 */
	public Address getCurrentAddress() {
		if (currentLocation1 != null) {
			return currentLocation1.getAddress();
		}
		return null;
	}
	
	/**
	 * Get the current function containing the UI cursor.
	 */
	public Function getCurrentFunction() {
		Program program = getCurrentProgram();
		Address address = getCurrentAddress();
		
		if (program != null && address != null) {
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionContaining(address);
		}
		return null;
	}
}