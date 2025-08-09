/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames data elements (variables, labels) at a specific address.
 */
public class RenameDataTool implements McpTool {
    
    @Override
    public String getName() {
        return "rename_data";
    }
    
    @Override
    public String getDescription() {
        return "Rename data elements (variables, labels) at a specific address";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "new_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String addressStr = (String) arguments.get("address");
        String newName = (String) arguments.get("new_name");
        
        if (addressStr == null || newName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address and new_name parameters are required")
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
        
        // Try to find data at this address - wrap all operations in transaction
        int transactionID = currentProgram.startTransaction("Rename Data");
        try {
            Data data = currentProgram.getListing().getDataAt(address);
            if (data != null) {
                // Rename the data symbol
                Symbol primarySymbol = data.getPrimarySymbol();
                if (primarySymbol != null) {
                    String oldName = primarySymbol.getName();
                    try {
                        primarySymbol.setName(newName, SourceType.USER_DEFINED);
                        currentProgram.endTransaction(transactionID, true);
                        return McpSchema.CallToolResult.builder()
                            .addTextContent("Successfully renamed data at " + addressStr + 
                                          " from '" + oldName + "' to '" + newName + "'")
                            .build();
                    } catch (DuplicateNameException e) {
                        currentProgram.endTransaction(transactionID, false);
                        return McpSchema.CallToolResult.builder()
                            .addTextContent("Symbol with name '" + newName + "' already exists")
                            .build();
                    } catch (InvalidInputException e) {
                        currentProgram.endTransaction(transactionID, false);
                        return McpSchema.CallToolResult.builder()
                            .addTextContent("Invalid symbol name: " + newName)
                            .build();
                    }
                }
                // Create a new symbol for the data
                currentProgram.getSymbolTable().createLabel(address, newName, SourceType.USER_DEFINED);
                currentProgram.endTransaction(transactionID, true);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Successfully created label '" + newName + "' at " + addressStr)
                    .build();
            }
            // No data at address, try to find any symbol and rename it
            Symbol[] symbols = currentProgram.getSymbolTable().getSymbols(address);
            if (symbols.length > 0) {
                Symbol symbol = symbols[0]; // Use first symbol
                String oldName = symbol.getName();
                try {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    currentProgram.endTransaction(transactionID, true);
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Successfully renamed symbol at " + addressStr + 
                                      " from '" + oldName + "' to '" + newName + "'")
                        .build();
                } catch (DuplicateNameException e) {
                    currentProgram.endTransaction(transactionID, false);
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Symbol with name '" + newName + "' already exists")
                        .build();
                } catch (InvalidInputException e) {
                    currentProgram.endTransaction(transactionID, false);
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Invalid symbol name: " + newName)
                        .build();
                }
            }
            // Create a new label at the address
            currentProgram.getSymbolTable().createLabel(address, newName, SourceType.USER_DEFINED);
            currentProgram.endTransaction(transactionID, true);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully created label '" + newName + "' at " + addressStr)
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error creating label: " + e.getMessage())
                .build();
        }
    }
}