/*
 * MCP tool for modifying existing data structures in Ghidra.
 */
package ghidrassistmcp.tools;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that modifies existing user-defined data structures.
 * Can replace a structure's definition with a new C-language struct definition.
 */
public class ModifyStructTool implements McpTool {

    @Override
    public String getName() {
        return "modify_struct";
    }

    @Override
    public String getDescription() {
        return "Modify an existing structure by replacing it with a new C-language struct definition. " +
               "The structure name in the definition must match the target structure name, or use 'new_name' to rename.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "c_definition", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("structure_name", "c_definition"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String structureName = (String) arguments.get("structure_name");
        String cDefinition = (String) arguments.get("c_definition");
        String newName = (String) arguments.get("new_name");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        if (cDefinition == null || cDefinition.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("c_definition parameter is required")
                .build();
        }

        int txId = currentProgram.startTransaction("Modify Structure");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();

            // Find the existing structure
            Structure existingStruct = findStructure(dtm, structureName);
            if (existingStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found. " +
                        "Use create_struct to create a new structure.")
                    .build();
            }

            // Store the category path to preserve it
            var categoryPath = existingStruct.getCategoryPath();

            // Parse the new C definition
            Structure newStruct = parseStructFromCDefinition(dtm, cDefinition);
            if (newStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to parse C structure definition")
                    .build();
            }

            // Apply the new definition to the existing structure
            Structure result = applyNewDefinition(dtm, existingStruct, newStruct, newName, categoryPath);

            if (result == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to apply new structure definition")
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully modified structure '" + result.getName() +
                    "': now has " + result.getNumComponents() + " components, size " +
                    result.getLength() + " bytes")
                .build();

        } catch (Exception e) {
            String msg = "Error modifying structure: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    /**
     * Find a structure by name in the data type manager.
     */
    private Structure findStructure(DataTypeManager dtm, String structureName) {
        // Try common paths
        String[] searchPaths = {
            "/" + structureName,
            "/auto_structs/" + structureName,
            structureName
        };

        for (String path : searchPaths) {
            DataType dt = dtm.getDataType(path);
            if (dt instanceof Structure) {
                return (Structure) dt;
            }
        }

        // Search all data types if not found by path
        List<DataType> allTypes = new ArrayList<>();
        dtm.getAllDataTypes(allTypes);
        for (DataType dt : allTypes) {
            if (dt instanceof Structure && dt.getName().equals(structureName)) {
                return (Structure) dt;
            }
        }

        return null;
    }

    /**
     * Parse a structure from a C-language definition.
     */
    private Structure parseStructFromCDefinition(DataTypeManager dtm, String cDefinition) throws Exception {
        // Normalize the C definition
        String normalizedDef = cDefinition.trim();
        if (!normalizedDef.endsWith(";")) {
            normalizedDef += ";";
        }

        // Create a temporary CParser
        CParser parser = new CParser(dtm);

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                normalizedDef.getBytes(StandardCharsets.UTF_8));
            parser.parse(inputStream);

            Map<String, DataType> composites = parser.getComposites();

            if (composites.isEmpty()) {
                throw new Exception("No structure definition found in the provided C code. " +
                    "Make sure to use format: 'struct Name { type field; ... };'");
            }

            DataType parsedType = composites.values().iterator().next();

            if (!(parsedType instanceof Structure)) {
                throw new Exception("Parsed type is not a structure: " + parsedType.getName());
            }

            return (Structure) parsedType;

        } catch (ghidra.app.util.cparser.C.ParseException pe) {
            throw new Exception("C parse error: " + pe.getMessage() +
                ". Check your struct definition syntax.");
        }
    }

    /**
     * Apply a new structure definition to an existing structure.
     */
    private Structure applyNewDefinition(DataTypeManager dtm, Structure existingStruct,
                                         Structure newStruct, String newName,
                                         ghidra.program.model.data.CategoryPath categoryPath) throws Exception {
        // Clear existing components
        existingStruct.deleteAll();

        // Determine if packing should be enabled based on new struct
        boolean isPacked = newStruct.isPackingEnabled();
        existingStruct.setPackingEnabled(isPacked);

        // Copy components from new struct to existing struct
        DataTypeComponent[] components = newStruct.getDefinedComponents();
        for (DataTypeComponent comp : components) {
            DataType compType = comp.getDataType();
            int compLength = comp.getLength();
            String fieldName = comp.getFieldName();
            String comment = comp.getComment();
            int offset = comp.getOffset();

            // For non-packed structures, insert at specific offsets
            if (!isPacked && existingStruct.getLength() < offset) {
                // Grow structure to accommodate the offset
                existingStruct.growStructure(offset - existingStruct.getLength());
            }

            if (isPacked) {
                // For packed structures, just add components sequentially
                if (fieldName != null) {
                    existingStruct.add(compType, compLength, fieldName, comment);
                } else {
                    existingStruct.add(compType, compLength, null, comment);
                }
            } else {
                // For non-packed structures, insert at specific offsets
                try {
                    existingStruct.replaceAtOffset(offset, compType, compLength, fieldName, comment);
                } catch (Exception e) {
                    // If replaceAtOffset fails, try insertAtOffset
                    existingStruct.insertAtOffset(offset, compType, compLength, fieldName, comment);
                }
            }
        }

        // Handle renaming if requested
        if (newName != null && !newName.isEmpty() && !newName.equals(existingStruct.getName())) {
            try {
                existingStruct.setName(newName);
            } catch (Exception e) {
                Msg.warn(this, "Could not rename structure to '" + newName + "': " + e.getMessage());
            }
        }

        Msg.info(this, "Modified structure: " + existingStruct.getName() +
            " with " + existingStruct.getNumComponents() + " components");

        return existingStruct;
    }
}
