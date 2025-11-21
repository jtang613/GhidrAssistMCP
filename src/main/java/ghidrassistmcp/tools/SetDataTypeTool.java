/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets the data type at a specific address.
 */
public class SetDataTypeTool implements McpTool {
    
    @Override
    public String getName() {
        return "set_data_type";
    }
    
    @Override
    public String getDescription() {
        return "Set the data type at a specific address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_type", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "data_type"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String addressStr = (String) arguments.get("address");
        String dataTypeName = (String) arguments.get("data_type");
        
        if (addressStr == null || dataTypeName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address and data_type parameters are required")
                .build();
        }
        
        // Parse the address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr)
                .build();
        }
        
        // Find the data type
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = dtm.getDataType("/" + dataTypeName);
        if (dataType == null) {
            // Try finding by name without path
            dataType = dtm.getDataType(dataTypeName);
        }
        
        if (dataType == null) {
             // Search for type in all categories if simple lookup failed
             var allTypes = new java.util.ArrayList<DataType>();
             dtm.getAllDataTypes(allTypes);
             for (DataType dt : allTypes) {
                 if (dt.getName().equals(dataTypeName)) {
                     dataType = dt;
                     break;
                 }
             }
        }

        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + dataTypeName + 
                              ". Use built-in types like 'int', 'char', 'void*', etc.")
                .build();
        }
        
        // Start transaction
        int transactionID = currentProgram.startTransaction("Set Data Type");
        try {
            // If fixed length, clear the area first
            if (dataType.getLength() > 0) {
                currentProgram.getListing().clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
            } else {
                // For dynamic length, clear the current code unit at address
                currentProgram.getListing().clearCodeUnits(address, address, false);
            }
            
            currentProgram.getListing().createData(address, dataType);
            
            currentProgram.endTransaction(transactionID, true);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully set data type at " + addressStr + " to " + dataType.getName())
                .build();
        } catch (CodeUnitInsertionException e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting data type (overlap or conflict): " + e.getMessage())
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting data type: " + e.getMessage())
                .build();
        }
    }
}
