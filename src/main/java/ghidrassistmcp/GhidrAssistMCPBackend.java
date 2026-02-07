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
import ghidrassistmcp.cache.McpCache;
import ghidrassistmcp.prompts.AnalyzeFunctionPrompt;
import ghidrassistmcp.prompts.DocumentFunctionPrompt;
import ghidrassistmcp.prompts.IdentifyVulnerabilityPrompt;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.prompts.McpPromptRegistry;
import ghidrassistmcp.prompts.TraceDataFlowPrompt;
import ghidrassistmcp.prompts.TraceNetworkDataPrompt;
import ghidrassistmcp.resources.ExportsResource;
import ghidrassistmcp.resources.FunctionListResource;
import ghidrassistmcp.resources.ImportsResource;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.resources.McpResourceRegistry;
import ghidrassistmcp.resources.ProgramInfoResource;
import ghidrassistmcp.resources.StringsResource;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskManager;
import ghidrassistmcp.tools.BookmarksTool;
import ghidrassistmcp.tools.CancelTaskTool;
import ghidrassistmcp.tools.ClassTool;
import ghidrassistmcp.tools.GetBasicBlocksTool;
import ghidrassistmcp.tools.GetCallGraphTool;
import ghidrassistmcp.tools.GetCodeTool;
import ghidrassistmcp.tools.GetCurrentAddressTool;
import ghidrassistmcp.tools.GetCurrentFunctionTool;
import ghidrassistmcp.tools.GetDataTypeTool;
import ghidrassistmcp.tools.GetFunctionInfoTool;
import ghidrassistmcp.tools.GetHexdumpTool;
import ghidrassistmcp.tools.GetTaskStatusTool;
import ghidrassistmcp.tools.ListDataTool;
import ghidrassistmcp.tools.ListDataTypesTool;
import ghidrassistmcp.tools.ListExportsTool;
import ghidrassistmcp.tools.ListProgramsTool;
import ghidrassistmcp.tools.ListFunctionsTool;
import ghidrassistmcp.tools.ListImportsTool;
import ghidrassistmcp.tools.ListNamespacesTool;
import ghidrassistmcp.tools.ListRelocationsTool;
import ghidrassistmcp.tools.ListSegmentsTool;
import ghidrassistmcp.tools.ListStringsTool;
import ghidrassistmcp.tools.ListTasksTool;
import ghidrassistmcp.tools.ProgramInfoTool;
import ghidrassistmcp.tools.RenameSymbolBatchTool;
import ghidrassistmcp.tools.RenameSymbolTool;
import ghidrassistmcp.tools.SearchBytesTool;
import ghidrassistmcp.tools.SetCommentTool;
import ghidrassistmcp.tools.SetDataTypeTool;
import ghidrassistmcp.tools.SetFunctionPrototypeTool;
import ghidrassistmcp.tools.SetLocalVariableTypeTool;
import ghidrassistmcp.tools.StructTool;
import ghidrassistmcp.tools.XrefsTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Implementation of the MCP backend that manages tools and program state.
 * Works with the singleton GhidrAssistMCPManager to support multiple CodeBrowser windows.
 */
public class GhidrAssistMCPBackend implements McpBackend {

    private final Map<String, McpTool> tools = new ConcurrentHashMap<>();
    private final Map<String, Boolean> toolEnabledStates = new ConcurrentHashMap<>();
    private final List<McpEventListener> eventListeners = new CopyOnWriteArrayList<>();
    private volatile GhidrAssistMCPManager manager;
    private final McpTaskManager taskManager;
    private final McpResourceRegistry resourceRegistry;
    private final McpPromptRegistry promptRegistry;
    private final McpCache cache;
    
    public GhidrAssistMCPBackend() {
        // Initialize task manager for async operations
        this.taskManager = new McpTaskManager();

        // Initialize resource registry
        this.resourceRegistry = new McpResourceRegistry();
        registerBuiltinResources();

        // Initialize prompt registry
        this.promptRegistry = new McpPromptRegistry();
        registerBuiltinPrompts();

        // Initialize result cache
        this.cache = new McpCache();

        // Register built-in tools
        registerTool(new ProgramInfoTool());
        registerTool(new ListFunctionsTool());
        registerTool(new GetFunctionInfoTool());
        registerTool(new ListSegmentsTool());
        registerTool(new ListImportsTool());
        registerTool(new ListExportsTool());
        registerTool(new ListStringsTool());
        registerTool(new GetCurrentAddressTool());
        registerTool(new GetHexdumpTool());
        registerTool(new GetCurrentFunctionTool());
        registerTool(new GetDataTypeTool());
        registerTool(new ListDataTool());
        registerTool(new ListDataTypesTool());
        registerTool(new ListNamespacesTool());
        registerTool(new ListProgramsTool());
        registerTool(new ClassTool());
        registerTool(new SetFunctionPrototypeTool());
        registerTool(new SetLocalVariableTypeTool());
        registerTool(new SetDataTypeTool());

        // Register async task management tools
        registerTool(new GetTaskStatusTool());
        registerTool(new CancelTaskTool());
        registerTool(new ListTasksTool());

        // Register consolidated and advanced tools
        registerTool(new GetCodeTool());
        registerTool(new SetCommentTool());
        registerTool(new RenameSymbolTool());
        registerTool(new RenameSymbolBatchTool());
        registerTool(new XrefsTool());
        registerTool(new StructTool());
        registerTool(new GetCallGraphTool());
        registerTool(new SearchBytesTool());
        registerTool(new BookmarksTool());
        registerTool(new GetBasicBlocksTool());
        registerTool(new ListRelocationsTool());

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
                // Augment the schema with program_name parameter for multi-program support
                McpSchema.JsonSchema augmentedSchema = augmentSchemaWithProgramName(tool.getInputSchema());

                // Build tool annotations based on McpTool interface methods
                McpSchema.ToolAnnotations annotations = new McpSchema.ToolAnnotations(
                    null,  // title - will use tool name
                    tool.isReadOnly(),
                    tool.isDestructive(),
                    tool.isIdempotent(),
                    tool.isOpenWorld(),
                    null   // returnDirect
                );

                toolList.add(McpSchema.Tool.builder()
                    .name(tool.getName())
                    .title(tool.getName())
                    .description(tool.getDescription())
                    .inputSchema(augmentedSchema)
                    .annotations(annotations)
                    .build());
            }
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }

    /**
     * Augment a tool's input schema with the universal 'program_name' parameter.
     * This allows all tools to optionally target a specific open program.
     */
    private McpSchema.JsonSchema augmentSchemaWithProgramName(McpSchema.JsonSchema originalSchema) {
        // Create the program_name property schema
        Map<String, Object> programNameSchema = new HashMap<>();
        programNameSchema.put("type", "string");
        programNameSchema.put("description", "Optional: Name of the program/binary to operate on. " +
            "Use list_programs to see available programs. " +
            "If not specified, uses the currently active program.");

        if (originalSchema == null) {
            // Create a schema with just program_name
            Map<String, Object> props = new HashMap<>();
            props.put("program_name", programNameSchema);
            return new McpSchema.JsonSchema("object", props, List.of(), null, null, null);
        }

        // Get original properties or empty map
        Map<String, Object> originalProps = originalSchema.properties();
        Map<String, Object> newProps;

        if (originalProps != null) {
            newProps = new HashMap<>(originalProps);
        } else {
            newProps = new HashMap<>();
        }

        // Add program_name parameter
        newProps.put("program_name", programNameSchema);

        // Return new schema with augmented properties
        return new McpSchema.JsonSchema(
            originalSchema.type(),
            newProps,
            originalSchema.required(),
            originalSchema.additionalProperties(),
            originalSchema.defs(),
            originalSchema.definitions()
        );
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

            // Resolve the target program - check if program_name is specified
            Program targetProgram = resolveTargetProgram(arguments);

            // Check cache for cacheable tools
            if (tool.isCacheable() && targetProgram != null) {
                String cacheKey = cache.generateKey(toolName, arguments, targetProgram.getName());
                McpSchema.CallToolResult cachedResult = cache.get(cacheKey, targetProgram);
                if (cachedResult != null) {
                    Msg.info(this, "Cache hit for tool: " + toolName);
                    notifyToolResponse(toolName, cachedResult);
                    return cachedResult;
                }
            }

            // Check if this is a long-running tool that should be executed asynchronously
            if (tool.isLongRunning()) {
                return executeToolAsync(tool, toolName, arguments, targetProgram);
            }

            // Execute synchronously for normal tools
            McpSchema.CallToolResult result = tool.execute(arguments, targetProgram, this);

            // Add active context information to help LLM understand which binary is in focus
            result = addActiveContextToResult(result, targetProgram);

            // Cache the result if tool is cacheable
            if (tool.isCacheable() && targetProgram != null) {
                String cacheKey = cache.generateKey(toolName, arguments, targetProgram.getName());
                cache.put(cacheKey, result, targetProgram);
                Msg.debug(this, "Cached result for tool: " + toolName);
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

    /**
     * Execute a long-running tool asynchronously and return a task ID.
     */
    private McpSchema.CallToolResult executeToolAsync(McpTool tool, String toolName,
                                                       Map<String, Object> arguments, Program targetProgram) {
        // Create a reference to this backend for the async execution
        final GhidrAssistMCPBackend backend = this;

        McpTask task = taskManager.submitTask(toolName, arguments, () -> {
            try {
                McpSchema.CallToolResult result = tool.execute(arguments, targetProgram, backend);
                result = addActiveContextToResult(result, targetProgram);
                notifyToolResponse(toolName, result);
                return result;
            } catch (Exception e) {
                Msg.error(this, "Async tool execution failed: " + toolName, e);
                throw new RuntimeException(e);
            }
        });

        // Return task information immediately
        return McpSchema.CallToolResult.builder()
            .addTextContent("Task submitted for async execution.\n\n" +
                "Task ID: " + task.getTaskId() + "\n" +
                "Tool: " + toolName + "\n" +
                "Status: " + task.getStatus() + "\n\n" +
                "Use get_task_status with this task_id to check progress and retrieve results.\n" +
                "Use cancel_task to cancel if needed.")
            .build();
    }

    /**
     * Get the task manager for async operations.
     */
    public McpTaskManager getTaskManager() {
        return taskManager;
    }

    /**
     * Get the resource registry.
     */
    public McpResourceRegistry getResourceRegistry() {
        return resourceRegistry;
    }

    /**
     * Register built-in MCP resources.
     */
    private void registerBuiltinResources() {
        resourceRegistry.registerResource(new ProgramInfoResource());
        resourceRegistry.registerResource(new FunctionListResource());
        resourceRegistry.registerResource(new StringsResource());
        resourceRegistry.registerResource(new ImportsResource());
        resourceRegistry.registerResource(new ExportsResource());
        Msg.info(this, "Registered " + resourceRegistry.getResourceCount() + " MCP resources");
    }

    /**
     * Register built-in MCP prompts.
     */
    private void registerBuiltinPrompts() {
        promptRegistry.registerPrompt(new AnalyzeFunctionPrompt());
        promptRegistry.registerPrompt(new IdentifyVulnerabilityPrompt());
        promptRegistry.registerPrompt(new DocumentFunctionPrompt());
        promptRegistry.registerPrompt(new TraceDataFlowPrompt());
        promptRegistry.registerPrompt(new TraceNetworkDataPrompt());
        Msg.info(this, "Registered " + promptRegistry.getPromptCount() + " MCP prompts");
    }

    /**
     * Get the prompt registry.
     */
    public McpPromptRegistry getPromptRegistry() {
        return promptRegistry;
    }

    /**
     * Get available prompts for the MCP SDK.
     */
    public List<McpPrompt> getAvailablePrompts() {
        return promptRegistry.getAllPrompts();
    }

    /**
     * Get the result cache.
     */
    public McpCache getCache() {
        return cache;
    }

    /**
     * Get cache statistics summary.
     */
    public String getCacheStats() {
        return cache.getStats();
    }

    /**
     * Clear the cache (e.g., when program is significantly modified).
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Read a resource by URI.
     *
     * @param uri The resource URI
     * @return The resource content
     */
    public String readResource(String uri) {
        Program program = getCurrentProgram();
        return resourceRegistry.readResource(uri, program);
    }

    /**
     * Get available resources for the MCP SDK.
     */
    public List<McpResource> getAvailableResources() {
        return resourceRegistry.getAllResources();
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
            .resources(false, false)  // subscribe=false, listChanged=false
            .prompts(false)           // listChanged=false
            .build();
    }
    
    /**
     * Resolve the target program based on arguments.
     * If 'program_name' is specified, look up that program across ALL open tools.
     * Otherwise, return the currently active program.
     *
     * @param arguments The tool arguments that may contain 'program_name'
     * @return The resolved program to operate on
     */
    private Program resolveTargetProgram(Map<String, Object> arguments) {
        if (manager == null) {
            return null;
        }

        // Check if a specific program was requested
        Object programNameObj = arguments.get("program_name");
        if (programNameObj instanceof String) {
            String programName = (String) programNameObj;
            if (!programName.trim().isEmpty()) {
                Program found = manager.getProgramByName(programName);
                if (found != null) {
                    Msg.info(this, "Resolved program by name: " + found.getName());
                    return found;
                }
                Msg.warn(this, "Program not found: " + programName + ", using current program");
            }
        }

        // Default to current program
        return manager.getCurrentProgram();
    }

    /**
     * Get the currently active program from the manager.
     * This queries ALL registered tools for the currently active program.
     */
    public Program getCurrentProgram() {
        if (manager != null) {
            return manager.getCurrentProgram();
        }
        return null;
    }

    /**
     * Get all open programs from ALL registered tools.
     */
    public List<Program> getAllOpenPrograms() {
        if (manager != null) {
            return manager.getAllOpenPrograms();
        }
        return new ArrayList<>();
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
     * Set the manager reference for multi-tool program discovery.
     */
    public void setManager(GhidrAssistMCPManager manager) {
        this.manager = manager;
        Msg.info(this, "Manager reference set for multi-tool support");
    }

    /**
     * Get the currently active plugin instance for UI context access.
     * This allows tools to access current address, current function, etc.
     *
     * @return The active plugin instance, or null if none is active
     */
    public GhidrAssistMCPPlugin getActivePlugin() {
        if (manager != null) {
            return manager.getActivePlugin();
        }
        return null;
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
    @SuppressWarnings("unused")
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
     * Add active context information to tool results to help LLM understand which binary is in focus.
     * This prepends context metadata to the first text content in the result.
     */
    private McpSchema.CallToolResult addActiveContextToResult(McpSchema.CallToolResult result, Program targetProgram) {
        if (result == null || result.content() == null || result.content().isEmpty()) {
            return result;
        }

        // Build context information
        StringBuilder contextInfo = new StringBuilder();

        // Get the current active program from manager
        Program activeProgram = getCurrentProgram();

        // Add context header
        contextInfo.append("[Context] ");

        if (targetProgram != null) {
            contextInfo.append("Operating on: ").append(targetProgram.getName());

            // If active program is different, mention it
            if (activeProgram != null && !activeProgram.equals(targetProgram)) {
                contextInfo.append(" | Active window: ").append(activeProgram.getName());
            }
        } else if (activeProgram != null) {
            contextInfo.append("Active window: ").append(activeProgram.getName());
        } else {
            contextInfo.append("No program currently active");
        }

        // Add available programs count if multiple are open
        if (manager != null) {
            List<Program> allPrograms = manager.getAllOpenPrograms();
            if (allPrograms.size() > 1) {
                contextInfo.append(" | Total open programs: ").append(allPrograms.size());
            }
        }

        contextInfo.append("\n\n");

        // Prepend context to the first text content
        var firstContent = result.content().get(0);
        if (firstContent instanceof McpSchema.TextContent) {
            String originalText = ((McpSchema.TextContent) firstContent).text();
            String enhancedText = contextInfo.toString() + originalText;

            // Build new result with enhanced content
            McpSchema.CallToolResult.Builder builder = McpSchema.CallToolResult.builder()
                .addTextContent(enhancedText);

            // Add remaining content items if any
            for (int i = 1; i < result.content().size(); i++) {
                var content = result.content().get(i);
                if (content instanceof McpSchema.TextContent) {
                    builder.addTextContent(((McpSchema.TextContent) content).text());
                }
            }

            return builder.build();
        }

        return result;
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
