# GhidrAssistMCP

A powerful Ghidra extension that provides an MCP (Model Context Protocol) server, enabling AI assistants and other tools to interact with Ghidra's reverse engineering capabilities through a standardized API.

## Overview

GhidrAssistMCP bridges the gap between AI-powered analysis tools and Ghidra's comprehensive reverse engineering platform. By implementing the Model Context Protocol, this extension allows external AI assistants, automated analysis tools, and custom scripts to seamlessly interact with Ghidra's analysis capabilities.

### Key Features

- **MCP Server Integration**: Full Model Context Protocol server implementation using official SDK
- **Dual HTTP Transports**: Supports SSE and Streamable HTTP transports for maximum client compatibility
- **38 Built-in Tools**: Comprehensive set of analysis tools covering functions, data, cross-references, structures, and more
- **Configurable UI**: Easy-to-use interface for managing tools and monitoring activity
- **Real-time Logging**: Track all MCP requests and responses with detailed logging
- **Dynamic Tool Management**: Enable/disable tools individually with persistent settings
- **Current Context Awareness**: Tools that understand Ghidra's current cursor position and active function

## Clients

Shameless self-promotion: [GhidrAssist](https://github.com/jtang613/GhidrAssist) supports GhidrAssistMCP right out of the box.

## Screenshots

![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot1.png)
![Screenshot](https://github.com/jtang613/GhidrAssistMCP/blob/master/res/Screenshot2.png)


## Installation

### Prerequisites

- **Ghidra 11.4+** (tested with Ghidra 11.4 Public)
- **An MCP Client (Like GhidrAssist)**

### Binary Release (Recommended)

1. **Download the latest release**:
   - Go to the [Releases page](https://github.com/jtang613/GhidrAssistMCP/releases)
   - Download the latest `.zip` file (e.g., `GhidrAssistMCP-v1.0.0.zip`)

2. **Install the extension**:
   - In Ghidra: **File → Install Extensions → Add Extension**
   - Select the downloaded ZIP file
   - Restart Ghidra when prompted

3. **Enable the plugin**:
   - **File → Configure → Configure Plugins**
   - Search for "GhidrAssistMCP"
   - Check the box to enable the plugin

### Building from Source

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd GhidrAssistMCP
   ```

2. **Set Ghidra installation path**:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/your/ghidra/installation
   ```

3. **Build the extension**:
   ```bash
   gradle buildExtension
   ```

4. **Install the extension**:
   - Copy the generated ZIP file from `dist/` directory
   - In Ghidra: **File → Install Extensions → Add Extension**
   - Select the ZIP file and restart Ghidra

5. **Enable the plugin**:
   - **File → Configure → Configure Plugins**
   - Search for "GhidrAssistMCP"
   - Check the box to enable the plugin

## Configuration

### Initial Setup

1. **Open the Control Panel**:
   - Window → GhidrAssistMCP (or use the toolbar icon)

2. **Configure Server Settings**:
   - **Host**: Default is `localhost`
   - **Port**: Default is `8080`
   - **Enable/Disable**: Toggle the MCP server on/off

### Tool Management

The Configuration tab allows you to:
- **View all available tools** (38 total)
- **Enable/disable individual tools** using checkboxes
- **Save configuration** to persist across sessions
- **Monitor tool status** in real-time

### Available Tools

#### Program Analysis
- `get_program_info` - Get basic program information
- `list_functions` - List all functions in the program
- `list_data` - List data definitions
- `list_data_types` - List all available data types
- `list_strings` - List string references
- `list_imports` - List imported functions
- `list_exports` - List exported functions
- `list_segments` - List memory segments
- `list_namespaces` - List namespaces
- `list_classes` - List class definitions
- `list_methods` - List method definitions

#### Function Analysis
- `get_function_info` - Get detailed function information
- `get_class_info` - Get detailed class information
- `get_function_by_address` - Find function at specific address
- `get_current_function` - Get function at cursor position
- `decompile_function` - Decompile function to C-like code
- `disassemble_function` - Get assembly disassembly
- `search_functions` - Search functions by name pattern
- `search_classes` - Search classes by name pattern
- `function_xrefs` - Get function cross-references

#### Location & Navigation
- `get_current_address` - Get current cursor address
- `get_hexdump` - Get hexdump of memory at specific address
- `xrefs_to` - Find references to an address
- `xrefs_from` - Find references from an address

#### Modification Tools
- `rename_function` - Rename functions
- `rename_function_by_address` - Rename function at specific address
- `rename_variable` - Rename variables
- `rename_data` - Rename data definitions
- `set_function_prototype` - Set function signatures
- `set_local_variable_type` - Set variable data types
- `set_disassembly_comment` - Add disassembly comments
- `set_decompiler_comment` - Add decompiler comments

#### Structure & Data Type Management
- `get_data_type` - Get detailed data type information and structure definitions
- `create_struct` - Create new user-defined structures
- `modify_struct` - Modify existing structures with C definitions
- `rename_structure_field` - Rename fields within structures
- `set_data_type` - Set data type at specific address
- `auto_create_struct` - Automatically create structures from variable usage patterns

## Usage Examples

### Basic Program Information

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_program_info"
  }
}
```

### Function Analysis

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_function_info",
    "arguments": {
      "function_name": "main"
    }
  }
}
```

### Decompilation

```json
{
  "method": "tools/call",
  "params": {
    "name": "decompile_function",
    "arguments": {
      "function_name": "encrypt_data"
    }
  }
}
```

### Structure Creation

```json
{
  "method": "tools/call",
  "params": {
    "name": "auto_create_struct",
    "arguments": {
      "function_identifier": "0x00401000",
      "variable_name": "ctx"
    }
  }
}
```

### Setting Function Prototype

```json
{
  "method": "tools/call",
  "params": {
    "name": "set_function_prototype",
    "arguments": {
      "function_address": "0x00401000",
      "prototype": "int main(int argc, char** argv)"
    }
  }
}
```

## Architecture

### Core Components

```
GhidrAssistMCP/
├── GhidrAssistMCPPlugin      # Main plugin entry point
├── GhidrAssistMCPServer      # HTTP MCP server (SSE + Streamable)
├── GhidrAssistMCPBackend     # Tool management and execution
├── GhidrAssistMCPProvider    # UI component provider
└── tools/                    # Individual MCP tools
    ├── Analysis Tools/
    ├── Modification Tools/
    └── Navigation Tools/
```

### MCP Protocol Implementation

- **Transports**:
  - HTTP with Server-Sent Events (SSE)
  - Streamable HTTP
- **Endpoints**:
  - `GET /sse` - SSE connection for bidirectional communication
  - `POST /message` - Message exchange endpoint
  - `GET /mcp` - Receive Streamable HTTP events
  - `POST /mcp` - Initialize Streamable HTTP session
  - `DELETE /mcp` - Terminate Streamable HTTP session
- **Tool Registration**: Dynamic tool discovery and registration
- **Session Management**: Stateful sessions with proper lifecycle management

### Plugin Architecture

1. **Observer Pattern**: Decoupled UI updates using event listeners
2. **Transaction Management**: Safe database operations with rollback support
3. **Tool Registry**: Dynamic tool registration with enable/disable capability
4. **Settings Persistence**: Configuration saved in Ghidra's settings system
5. **Thread Safety**: Proper Swing EDT handling for UI operations

## Development

### Project Structure

```
src/main/java/ghidrassistmcp/
├── GhidrAssistMCPPlugin.java      # Main plugin class
├── GhidrAssistMCPProvider.java    # UI provider with tabs
├── GhidrAssistMCPServer.java      # MCP server implementation
├── GhidrAssistMCPBackend.java     # Backend tool management
├── McpBackend.java                # Backend interface
├── McpTool.java                   # Tool interface
├── McpEventListener.java          # Event notification interface
└── tools/                         # Tool implementations
    ├── ProgramInfoTool.java
    ├── ListFunctionsTool.java
    ├── DecompileFunctionTool.java
    ├── AutoCreateStructTool.java
    └── ... (38 total tools)
```

### Adding New Tools

1. **Implement McpTool interface**:
   ```java
   public class MyCustomTool implements McpTool {
       @Override
       public String getName() { return "my_custom_tool"; }
       
       @Override
       public String getDescription() { return "Description"; }
       
       @Override
       public McpSchema.JsonSchema getInputSchema() { /* ... */ }
       
       @Override
       public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
           // Implementation
       }
   }
   ```

2. **Register in backend**:
   ```java
   // In GhidrAssistMCPBackend constructor
   registerTool(new MyCustomTool());
   ```

### Build Commands

```bash
# Clean build
gradle clean

# Build extension
gradle buildExtension

# Build with specific Ghidra path
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension

# Debug build
gradle buildExtension --debug
```

### Dependencies

- **MCP SDK**: `io.modelcontextprotocol.sdk:mcp:0.10.0`
- **Jetty Server**: `11.0.20` (HTTP/SSE transport)
- **Jackson**: `2.17.0` (JSON processing)
- **Ghidra API**: Bundled with Ghidra installation

## Logging

### UI Logging

The **Log** tab provides real-time monitoring:
- **Session Events**: Server start/stop, program changes
- **Tool Requests**: `REQ: tool_name {parameters...}`
- **Tool Responses**: `RES: tool_name {response...}`
- **Error Messages**: Failed operations and diagnostics

### Console Logging

Detailed logging in Ghidra's console:
- Tool registration and initialization
- MCP server lifecycle events
- Database transaction operations
- Error stack traces and debugging information

## Troubleshooting

### Common Issues

**Server Won't Start**
- Check if port 8080 is available
- Verify Ghidra installation path
- Examine console logs for errors

**Tools Not Appearing**
- Ensure plugin is enabled
- Check Configuration tab for tool status
- Verify backend initialization in logs

**MCP Client Connection Issues**
- Confirm server is running (check GhidrAssistMCP window)
- Test connection: `curl http://localhost:8080/sse`
- Check firewall settings

**Tool Execution Failures**
- Verify program is loaded in Ghidra
- Check tool parameters are correct
- Review error messages in Log tab

### Debug Mode

Enable debug logging by adding to Ghidra startup:
```bash
-Dlog4j.logger.ghidrassistmcp=DEBUG
```

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper tests
4. **Follow code style**: Use existing patterns and conventions
5. **Submit a pull request** with detailed description

### Code Standards

- **Java 21+ features** where appropriate
- **Proper exception handling** with meaningful messages
- **Transaction safety** for all database operations
- **Thread safety** for UI operations
- **Comprehensive documentation** for public APIs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **NSA/Ghidra Team** for the excellent reverse engineering platform
- **Anthropic** for the Model Context Protocol specification

---

**Questions or Issues?**

Please open an issue on the project repository for bug reports, feature requests, or questions about usage and development.
