/*
 * MCP tool for creating user-defined data structures in Ghidra.
 */
package ghidrassistmcp.tools;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that creates user-defined data structures.
 * Supports creating empty structures or structures from C-language definitions.
 */
public class CreateStructTool implements McpTool {

    @Override
    public String getName() {
        return "create_struct";
    }

    @Override
    public String getDescription() {
        return "Create a new user-defined structure. Can create an empty structure or parse a C-language struct definition.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "size", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "c_definition", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "category", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "packed", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
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

        String name = (String) arguments.get("name");
        String cDefinition = (String) arguments.get("c_definition");
        String category = (String) arguments.get("category");
        Number sizeNum = (Number) arguments.get("size");
        Boolean packed = (Boolean) arguments.get("packed");

        // Validate input - need either name or c_definition
        if ((name == null || name.isEmpty()) && (cDefinition == null || cDefinition.isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either 'name' (for empty struct) or 'c_definition' must be provided")
                .build();
        }

        int txId = currentProgram.startTransaction("Create Structure");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Structure result;

            if (cDefinition != null && !cDefinition.isEmpty()) {
                // Parse C definition
                result = createStructFromCDefinition(dtm, cDefinition, category);
            } else {
                // Create empty structure
                int size = sizeNum != null ? sizeNum.intValue() : 0;
                result = createEmptyStruct(dtm, name, size, category, packed != null && packed);
            }

            if (result == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to create structure")
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully created structure '" + result.getName() +
                    "' with " + result.getNumComponents() + " components, size " +
                    result.getLength() + " bytes at category " + result.getCategoryPath())
                .build();

        } catch (Exception e) {
            String msg = "Error creating structure: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    /**
     * Create an empty structure with the specified name and size.
     */
    private Structure createEmptyStruct(DataTypeManager dtm, String name, int size,
                                        String category, boolean packed) {
        CategoryPath categoryPath = category != null && !category.isEmpty()
            ? new CategoryPath(category)
            : CategoryPath.ROOT;

        // Create the structure
        StructureDataType struct = new StructureDataType(categoryPath, name, size, dtm);

        if (packed) {
            struct.setPackingEnabled(true);
        }

        // Add to data type manager
        DataType addedType = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        if (addedType instanceof Structure) {
            Msg.info(this, "Created empty structure: " + name);
            return (Structure) addedType;
        }

        return null;
    }

    /**
     * Create a structure from a C-language definition.
     */
    private Structure createStructFromCDefinition(DataTypeManager dtm, String cDefinition,
                                                   String category) throws Exception {
        // Normalize the C definition - ensure it ends with semicolon
        String normalizedDef = cDefinition.trim();
        if (!normalizedDef.endsWith(";")) {
            normalizedDef += ";";
        }

        // Create a CParser to parse the definition
        CParser parser = new CParser(dtm);

        try {
            // Parse the C definition
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                normalizedDef.getBytes(StandardCharsets.UTF_8));
            parser.parse(inputStream);

            // Get the parsed composites (structures/unions)
            Map<String, DataType> composites = parser.getComposites();

            if (composites.isEmpty()) {
                throw new Exception("No structure definition found in the provided C code. " +
                    "Make sure to use format: 'struct Name { type field; ... };'");
            }

            // Get the first (or only) structure parsed
            DataType parsedType = composites.values().iterator().next();

            if (!(parsedType instanceof Structure)) {
                throw new Exception("Parsed type is not a structure: " + parsedType.getName());
            }

            Structure parsedStruct = (Structure) parsedType;

            // If category specified, move it there
            if (category != null && !category.isEmpty()) {
                CategoryPath categoryPath = new CategoryPath(category);
                parsedStruct.setCategoryPath(categoryPath);
            }

            // Add to data type manager
            DataType addedType = dtm.addDataType(parsedStruct, DataTypeConflictHandler.REPLACE_HANDLER);

            if (addedType instanceof Structure) {
                Msg.info(this, "Created structure from C definition: " + addedType.getName());
                return (Structure) addedType;
            }

            return null;

        } catch (ghidra.app.util.cparser.C.ParseException pe) {
            throw new Exception("C parse error: " + pe.getMessage() +
                ". Check your struct definition syntax.");
        }
    }
}
