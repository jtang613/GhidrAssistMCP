/* 
 * 
 */
package ghidrassistmcp;

import java.time.Duration;
import java.util.Map;
import java.util.function.BiFunction;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Refactored MCP Server implementation that uses the backend architecture.
 * This class handles HTTP transport and delegates business logic to McpBackend.
 */
public class GhidrAssistMCPServer {
    
    private final McpBackend backend;
    private final GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private final int port;
    
    public GhidrAssistMCPServer(int port, McpBackend backend) {
        this(port, backend, null);
    }
    
    public GhidrAssistMCPServer(int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this.port = port;
        this.backend = backend;
        this.provider = provider;
    }
    
    public void start() throws Exception {
        Msg.info(this, "Starting MCP Server initialization...");
        
        try {
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server(port);
            
            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            jettyServer.setHandler(context);
            
            // Create MCP transport provider using simple constructor
            Msg.info(this, "Creating MCP transport provider");
            McpJsonMapper mapper = McpJsonMapper.getDefault();
            String messageEndpoint = "message";
            
            HttpServletSseServerTransportProvider transportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .messageEndpoint(messageEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();
            
            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var serverBuilder = McpServer.sync(transportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());
            
            // Register each tool individually with its own handler
            for (McpSchema.Tool toolSchema : backend.getAvailableTools()) {
                String toolName = toolSchema.name();
                BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> toolHandler =
                    (exchange, request) -> {
                        // The backend now handles all logging through event listeners
                        Map<String, Object> params = request.arguments();
                        return backend.callTool(toolName, params);
                    };
                
                serverBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }
            
            serverBuilder.build();
            
            // Register MCP servlet - use root path since transport provider handles routing internally
            Msg.info(this, "Registering MCP servlet");
            
            try {
                ServletHolder mcpServletHolder = new ServletHolder("mcp-transport", transportProvider);
                mcpServletHolder.setAsyncSupported(true);
                context.addServlet(mcpServletHolder, "/*");
                Msg.info(this, "Successfully registered MCP servlet for all paths: /*");
                
                // Log configuration
                Msg.info(this, "Transport provider class: " + transportProvider.getClass().getName());
                Msg.info(this, "Message endpoint configured as: " + messageEndpoint);
                Msg.info(this, "SSE endpoint will be: /sse (default)");
                Msg.info(this, "Expected client URLs:");
                Msg.info(this, "  SSE: http://localhost:" + port + "/sse");
                Msg.info(this, "  Messages: http://localhost:" + port + "/" + messageEndpoint);
                
            } catch (Exception e) {
                Msg.error(this, "Failed to register MCP servlet", e);
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP SSE endpoint: http://localhost:" + port + "/sse");
                Msg.info(this, "MCP message endpoint: http://localhost:" + port + "/" + messageEndpoint);
                Msg.info(this, "Server state: " + jettyServer.getState());
                
                // Log all registered servlets
                var servletHandler = context.getServletHandler();
                var servletMappings = servletHandler.getServletMappings();
                Msg.info(this, "Registered servlet mappings:");
                for (var mapping : servletMappings) {
                    Msg.info(this, "  " + mapping.getServletName() + " -> " + String.join(", ", mapping.getPathSpecs()));
                }
                
                // Log server startup to UI
                if (provider != null) {
                    provider.logSession("Jetty server listening on port " + port);
                    provider.logSession("Registered " + backend.getAvailableTools().size() + " MCP tools");
                    provider.logSession("Ready for MCP client connections");
                }
            } else {
                Msg.error(this, "Failed to start Jetty server - server not in started state");
            }
            
        } catch (Exception e) {
            Msg.error(this, "Exception during MCP Server startup: " + e.getMessage(), e);
            throw e;
        }
    }
    
    public void stop() throws Exception {
        if (jettyServer != null) {
            jettyServer.stop();
            Msg.info(this, "GhidrAssistMCP Server stopped");
        }
    }
    
    public void setCurrentProgram(Program program) {
        backend.onProgramActivated(program);
    }
    
}