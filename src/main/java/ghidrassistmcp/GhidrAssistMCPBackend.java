/* 
 * 
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.tools.AutoCreateStructTool;
import ghidrassistmcp.tools.CreateStructTool;
import ghidrassistmcp.tools.DecompileFunctionTool;
import ghidrassistmcp.tools.DisassembleFunctionTool;
import ghidrassistmcp.tools.FunctionXrefsTool;
import ghidrassistmcp.tools.GetClassInfoTool;
import ghidrassistmcp.tools.GetCurrentAddressTool;
import ghidrassistmcp.tools.GetCurrentFunctionTool;
import ghidrassistmcp.tools.GetDataTypeTool;
import ghidrassistmcp.tools.GetFunctionByAddressTool;
import ghidrassistmcp.tools.GetFunctionInfoTool;
import ghidrassistmcp.tools.GetHexdumpTool;
import ghidrassistmcp.tools.ListClassesTool;
import ghidrassistmcp.tools.ListDataTool;
import ghidrassistmcp.tools.ListDataTypesTool;
import ghidrassistmcp.tools.ListExportsTool;
import ghidrassistmcp.tools.ListFunctionsTool;
import ghidrassistmcp.tools.ListImportsTool;
import ghidrassistmcp.tools.ListMethodsTool;
import ghidrassistmcp.tools.ListNamespacesTool;
import ghidrassistmcp.tools.ListSegmentsTool;
import ghidrassistmcp.tools.ListStringsTool;
import ghidrassistmcp.tools.ModifyStructTool;
import ghidrassistmcp.tools.ProgramInfoTool;
import ghidrassistmcp.tools.RenameDataTool;
import ghidrassistmcp.tools.RenameFunctionByAddressTool;
import ghidrassistmcp.tools.RenameFunctionTool;
import ghidrassistmcp.tools.RenameStructureFieldTool;
import ghidrassistmcp.tools.RenameVariableTool;
import ghidrassistmcp.tools.SearchClassesTool;
import ghidrassistmcp.tools.SearchFunctionsTool;
import ghidrassistmcp.tools.SetDataTypeTool;
import ghidrassistmcp.tools.SetDecompilerCommentTool;
import ghidrassistmcp.tools.SetDisassemblyCommentTool;
import ghidrassistmcp.tools.SetFunctionPrototypeTool;
import ghidrassistmcp.tools.SetLocalVariableTypeTool;
import ghidrassistmcp.tools.XrefsFromTool;
import ghidrassistmcp.tools.XrefsToTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Implementation of the MCP backend that manages tools and program state.
 */
public class GhidrAssistMCPBackend implements McpBackend {
    
    private final Map<String, McpTool> tools = new ConcurrentHashMap<>();
    private final Map<String, Boolean> toolEnabledStates = new ConcurrentHashMap<>();
    private final List<McpEventListener> eventListeners = new CopyOnWriteArrayList<>();
    private volatile GhidrAssistMCPPlugin plugin;
    
    public GhidrAssistMCPBackend() {
        // Register built-in tools
        registerTool(new ProgramInfoTool());
        registerTool(new ListFunctionsTool());
        registerTool(new GetFunctionInfoTool());
        registerTool(new DecompileFunctionTool());
        registerTool(new DisassembleFunctionTool());
        registerTool(new RenameFunctionTool());
        registerTool(new RenameFunctionByAddressTool());
        registerTool(new RenameVariableTool());
        registerTool(new XrefsToTool());
        registerTool(new XrefsFromTool());
        registerTool(new ListMethodsTool());
        registerTool(new ListSegmentsTool());
        registerTool(new ListImportsTool());
        registerTool(new ListExportsTool());
        registerTool(new ListStringsTool());
        registerTool(new SearchFunctionsTool());
        registerTool(new GetFunctionByAddressTool());
        registerTool(new GetCurrentAddressTool());
        registerTool(new GetHexdumpTool());
        registerTool(new GetCurrentFunctionTool());
        registerTool(new GetDataTypeTool());
        registerTool(new SetDisassemblyCommentTool());
        registerTool(new SetDecompilerCommentTool());
        registerTool(new ListDataTool());
        registerTool(new ListDataTypesTool());
        registerTool(new ListNamespacesTool());
        registerTool(new ListClassesTool());
        registerTool(new SearchClassesTool());
        registerTool(new GetClassInfoTool());
        registerTool(new RenameDataTool());
        registerTool(new FunctionXrefsTool());
        registerTool(new SetFunctionPrototypeTool());
        registerTool(new SetLocalVariableTypeTool());
        registerTool(new SetDataTypeTool());
        registerTool(new AutoCreateStructTool());
        registerTool(new CreateStructTool());
        registerTool(new ModifyStructTool());
        registerTool(new RenameStructureFieldTool());
        
        Msg.info(this, "GhidrAssistMCP Backend initialized with " + tools.size() + " tools");
    }
    
    @Override
    public void registerTool(McpTool tool) {
        tools.put(tool.getName(), tool);
        // Tools are enabled by default when registered
        toolEnabledStates.put(tool.getName(), true);
        Msg.info(this, "Registered MCP tool: " + tool.getName());
    }
    
    @Override
    public void unregisterTool(String toolName) {
        McpTool removed = tools.remove(toolName);
        toolEnabledStates.remove(toolName);
        if (removed != null) {
            Msg.info(this, "Unregistered MCP tool: " + toolName);
        }
    }
    
    @Override
    public List<McpSchema.Tool> getAvailableTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            // Only include enabled tools in the available tools list
            if (toolEnabledStates.getOrDefault(tool.getName(), true)) {
                toolList.add(McpSchema.Tool.builder()
                    .name(tool.getName())
                    .title(tool.getName())
                    .description(tool.getDescription())
                    .inputSchema(tool.getInputSchema())
                    .build());
            }
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }
    
    @Override
    public McpSchema.CallToolResult callTool(String toolName, Map<String, Object> arguments) {
        McpTool tool = tools.get(toolName);
        if (tool == null) {
            Msg.warn(this, "Tool not found: " + toolName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Tool not found: " + toolName)
                .build();
        }

        // Check if tool is enabled
        if (!toolEnabledStates.getOrDefault(toolName, true)) {
            Msg.warn(this, "Tool is disabled: " + toolName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Tool is disabled: " + toolName)
                .build();
        }

        try {
            // Notify listeners of the request
            notifyToolRequest(toolName, arguments);

            Msg.info(this, "Executing tool: " + toolName);

            // Get the current program dynamically from the plugin
            Program currentProgram = getCurrentProgram();

            // Use the enhanced execute method if plugin is available
            McpSchema.CallToolResult result;
            if (plugin != null) {
                result = tool.execute(arguments, currentProgram, plugin);
            } else {
                result = tool.execute(arguments, currentProgram);
            }

            // Notify listeners of the response
            notifyToolResponse(toolName, result);

            return result;
        } catch (Exception e) {
            Msg.error(this, "Error executing tool " + toolName, e);
            McpSchema.CallToolResult errorResult = McpSchema.CallToolResult.builder()
                .addTextContent("Error executing tool " + toolName + ": " + e.getMessage())
                .build();

            // Notify listeners of the error response
            notifyToolResponse(toolName, errorResult);

            return errorResult;
        }
    }
    
    @Override
    public void onProgramActivated(Program program) {
        // Program activation is now handled dynamically - no caching needed
        if (program != null) {
            Msg.info(this, "Program activated: " + program.getName());
            // Notify listeners for logging purposes
            notifySessionEvent("Program activated: " + program.getName());
        }
    }

    @Override
    public void onProgramDeactivated(Program program) {
        // Program deactivation is now handled dynamically - no state clearing needed
        if (program != null) {
            Msg.info(this, "Program deactivated: " + program.getName());
        }
    }
    
    @Override
    public McpSchema.Implementation getServerInfo() {
        return new McpSchema.Implementation("ghidrassistmcp", "1.0.0");
    }
    
    @Override
    public McpSchema.ServerCapabilities getCapabilities() {
        return McpSchema.ServerCapabilities.builder()
            .tools(true)
            .build();
    }
    
    /**
     * Get the currently active program from the plugin.
     * This dynamically retrieves the program, ensuring we always have the correct one
     * even when switching between files/programs.
     */
    public Program getCurrentProgram() {
        if (plugin != null) {
            return plugin.getCurrentProgram();
        }
        return null;
    }
    
    /**
     * Add an event listener for MCP operations.
     */
    public void addEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.add(listener);
            Msg.info(this, "Added MCP event listener: " + listener.getClass().getSimpleName() + " (total listeners: " + eventListeners.size() + ")");
        }
    }
    
    /**
     * Remove an event listener.
     */
    public void removeEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.remove(listener);
            Msg.info(this, "Removed MCP event listener: " + listener.getClass().getSimpleName());
        }
    }
    
    /**
     * Set the plugin reference for tools that need UI access.
     */
    public void setPlugin(GhidrAssistMCPPlugin plugin) {
        this.plugin = plugin;
        Msg.info(this, "Plugin reference set for UI-aware tool execution");
    }
    
    /**
     * Notify listeners of a tool request.
     */
    private void notifyToolRequest(String toolName, Map<String, Object> arguments) {
        String params = arguments != null ? arguments.toString() : "{}";
        if (params.length() > 60) {
            params = params.substring(0, 57) + "...";
        }
        
        Msg.info(this, "Notifying " + eventListeners.size() + " listeners of tool request: " + toolName);
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolRequest(toolName, params);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool request", e);
            }
        }
    }
    
    /**
     * Notify listeners of a tool response.
     */
    private void notifyToolResponse(String toolName, McpSchema.CallToolResult result) {
        String response = "Empty response";
        if (result != null && !result.content().isEmpty()) {
            var firstContent = result.content().get(0);
            if (firstContent instanceof McpSchema.TextContent) {
                response = ((McpSchema.TextContent) firstContent).text();
                if (response.length() > 60) {
                    response = response.substring(0, 57) + "...";
                }
            }
        }
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolResponse(toolName, response);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool response", e);
            }
        }
    }
    
    /**
     * Notify listeners of a session event.
     */
    private void notifySessionEvent(String event) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onSessionEvent(event);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of session event", e);
            }
        }
    }
    
    /**
     * Notify listeners of a general log message.
     */
    private void notifyLogMessage(String message) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onLogMessage(message);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of log message", e);
            }
        }
    }
    
    /**
     * Set the enabled state of a tool.
     */
    public void setToolEnabled(String toolName, boolean enabled) {
        if (tools.containsKey(toolName)) {
            toolEnabledStates.put(toolName, enabled);
            Msg.info(this, "Tool " + toolName + " " + (enabled ? "enabled" : "disabled"));
        }
    }
    
    /**
     * Get the enabled state of a tool.
     */
    public boolean isToolEnabled(String toolName) {
        return toolEnabledStates.getOrDefault(toolName, true);
    }
    
    /**
     * Get all tool enabled states.
     */
    public Map<String, Boolean> getToolEnabledStates() {
        return new HashMap<>(toolEnabledStates);
    }
    
    /**
     * Update multiple tool enabled states at once.
     */
    public void updateToolEnabledStates(Map<String, Boolean> newStates) {
        for (Map.Entry<String, Boolean> entry : newStates.entrySet()) {
            String toolName = entry.getKey();
            if (tools.containsKey(toolName)) {
                toolEnabledStates.put(toolName, entry.getValue());
            }
        }
        Msg.info(this, "Updated enabled states for " + newStates.size() + " tools");
    }
    
    /**
     * Get all tools (including disabled ones) for configuration purposes.
     */
    public List<McpSchema.Tool> getAllTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            toolList.add(McpSchema.Tool.builder()
                .name(tool.getName())
                .title(tool.getName())
                .description(tool.getDescription())
                .inputSchema(tool.getInputSchema())
                .build());
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }
}
