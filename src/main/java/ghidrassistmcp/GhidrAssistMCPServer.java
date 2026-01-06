/* 
 * 
 */
package ghidrassistmcp;

import java.time.Duration;
import java.util.Map;
import java.util.function.BiFunction;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
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
    private final String host;
    private final int port;
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null);
    }
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this.host = host;
        this.port = port;
        this.backend = backend;
        this.provider = provider;
    }
    
    public void start() throws Exception {
        Msg.info(this, "Starting MCP Server initialization...");
        
        try {
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server();
            
            ServerConnector connector = new ServerConnector(jettyServer);
            connector.setHost(host);
            connector.setPort(port);
            jettyServer.addConnector(connector);

            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            jettyServer.setHandler(context);
            
            // Create MCP transport provider using custom ObjectMapper that ignores unknown properties
            Msg.info(this, "Creating MCP transport provider");
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String messageEndpoint = "/message";
            String mcpEndpoint = "/mcp";

            HttpServletSseServerTransportProvider sseTransportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .messageEndpoint(messageEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            HttpServletStreamableServerTransportProvider streamableTransportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .mcpEndpoint(mcpEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var sseServerBuilder = McpServer.sync(sseTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());

            var streamableServerBuilder = McpServer.sync(streamableTransportProvider)
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

                sseServerBuilder.toolCall(toolSchema, toolHandler);
                streamableServerBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }

            sseServerBuilder.build();
            streamableServerBuilder.build();
            
            // Register MCP servlet - use root path since transport provider handles routing internally
            Msg.info(this, "Registering MCP servlet");
            
            try {
                ServletHolder mcpSseServletHolder = new ServletHolder("mcp-sse-transport", sseTransportProvider);
                mcpSseServletHolder.setAsyncSupported(true);
                context.addServlet(mcpSseServletHolder, "/sse");
                context.addServlet(mcpSseServletHolder, messageEndpoint);

                ServletHolder mcpStreamableServletHolder = new ServletHolder("mcp-streamable-transport", streamableTransportProvider);
                mcpStreamableServletHolder.setAsyncSupported(true);
                context.addServlet(mcpStreamableServletHolder, "/mcp/*");
                Msg.info(this, "Registered MCP SSE servlet mapping: /*");
                Msg.info(this, "Registered MCP Streamable servlet mapping: /mcp/*");
                
                // Log configuration
                Msg.info(this, "Transport provider class: " + sseTransportProvider.getClass().getName());
                Msg.info(this, "Message endpoint configured as: " + messageEndpoint);
                Msg.info(this, "SSE endpoint will be: /sse (default)");
                Msg.info(this, "Expected client URLs:");
                Msg.info(this, "  SSE: http://" + host + ":" + port + "/sse");
                Msg.info(this, "  Messages: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "Streamable HTTP transport provider class: " + streamableTransportProvider.getClass().getName());
                Msg.info(this, "Streamable MCP endpoint: http://" + host + ":" + port + mcpEndpoint);
                
            } catch (Exception e) {
                Msg.error(this, "Failed to register MCP servlet", e);
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP SSE endpoint: http://" + host + ":" + port + "/sse");
                Msg.info(this, "MCP message endpoint: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "MCP Streamable endpoint: http://" + host + ":" + port + mcpEndpoint);
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