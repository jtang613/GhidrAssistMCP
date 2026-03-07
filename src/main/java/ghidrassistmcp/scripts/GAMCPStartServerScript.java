package ghidrassistmcp.scripts;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPHeadlessServer;

/**
 * Headless GhidraScript that starts the GhidrAssistMCP server.
 * Designed to be run as a -preScript before GhidrAssistHL scripts so that
 * the MCP server is available for tool calls during ReAct analysis.
 *
 * Usage in analyzeHeadless:
 *   -preScript GAMCPStartServerScript.java
 *   -postScript GAHLQueryScript.java ...
 */
public class GAMCPStartServerScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.warn(this, "GAMCPStartServerScript: No program loaded, skipping MCP server start");
            return;
        }

        String host = "localhost";
        int port = 8080;

        // Parse optional arguments: host=... port=...
        String[] args = getScriptArgs();
        if (args != null) {
            for (String arg : args) {
                if (arg.startsWith("host=")) {
                    host = arg.substring(5);
                } else if (arg.startsWith("port=")) {
                    try {
                        port = Integer.parseInt(arg.substring(5));
                    } catch (NumberFormatException e) {
                        Msg.warn(this, "Invalid port argument, using default 8080");
                    }
                }
            }
        }

        GhidrAssistMCPHeadlessServer mcpServer = GhidrAssistMCPHeadlessServer.getInstance();

        if (mcpServer.isRunning()) {
            Msg.info(this, "MCP server already running, updating program reference");
            mcpServer.setProgram(currentProgram);
            return;
        }

        Msg.info(this, "Starting headless MCP server for: " + currentProgram.getName());
        mcpServer.start(currentProgram, host, port);
        Msg.info(this, "Headless MCP server ready on " + host + ":" + port);
    }
}
