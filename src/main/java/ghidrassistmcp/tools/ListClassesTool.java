/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists classes/structures defined in the program.
 */
public class ListClassesTool implements McpTool {
    
    @Override
    public String getName() {
        return "list_classes";
    }
    
    @Override
    public String getDescription() {
        return "List classes/structures defined in the program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "include_builtin", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        // Parse optional parameters
        int offset = 0;
        int limit = 100; // Default limit
        boolean includeBuiltin = false;
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        if (arguments.get("include_builtin") instanceof Boolean) {
            includeBuiltin = (Boolean) arguments.get("include_builtin");
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Classes/Structures in program");
        if (!includeBuiltin) {
            result.append(" (user-defined only)");
        }
        result.append(":\n\n");
        
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Iterator<DataType> dataTypes = dtm.getAllDataTypes();
        
        int count = 0;
        int totalCount = 0;
        
        while (dataTypes.hasNext()) {
            DataType dataType = dataTypes.next();
            
            // Only include composite types (structures, unions, classes)
            if (!(dataType instanceof Composite)) {
                continue;
            }
            
            // Skip built-in types if not requested
            if (!includeBuiltin) {
                CategoryPath categoryPath = dataType.getCategoryPath();
                if (categoryPath != null && categoryPath.toString().startsWith("/")) {
                    // Skip system/built-in types that are in root categories
                    String pathStr = categoryPath.toString();
                    if (pathStr.equals("/") || pathStr.startsWith("/windows") || 
                        pathStr.startsWith("/generic") || pathStr.startsWith("/builtin")) {
                        continue;
                    }
                }
            }
            
            totalCount++;
            
            // Apply offset
            if (totalCount <= offset) {
                continue;
            }
            
            // Apply limit
            if (count >= limit) {
                break;
            }
            
            Composite composite = (Composite) dataType;
            String typeName = "Unknown";
            if (dataType instanceof Structure) {
                typeName = "Struct";
            } else if (dataType instanceof Union) {
                typeName = "Union";
            }
            
            result.append("- ").append(dataType.getName())
                  .append(" [").append(typeName).append("]")
                  .append(" (").append(composite.getNumComponents()).append(" fields, ")
                  .append(dataType.getLength()).append(" bytes)");
            
            if (dataType.getCategoryPath() != null) {
                result.append(" in ").append(dataType.getCategoryPath());
            }
            
            result.append("\n");
            count++;
        }
        
        if (totalCount == 0) {
            if (includeBuiltin) {
                result.append("No composite types found in the program.");
            } else {
                result.append("No user-defined classes/structures found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" classes/structures");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}