package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool to rename a field in a structure.
 */
public class RenameStructureFieldTool implements McpTool {

    @Override
    public String getName() {
        return "rename_structure_field";
    }

    @Override
    public String getDescription() {
        return "Rename a field within a structure data type";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                // Name of the structure
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                // New name for the field
                "new_field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                // Current name of the field (optional if offset provided)
                "old_field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                // Byte offset of the field (optional if old_field_name provided)
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("structure_name", "new_field_name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String structureName = (String) arguments.get("structure_name");
        String newFieldName = (String) arguments.get("new_field_name");
        String oldFieldName = (String) arguments.get("old_field_name");
        Number offsetNum = (Number) arguments.get("offset");

        if (oldFieldName == null && offsetNum == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either old_field_name or offset must be provided to identify the field")
                .build();
        }

        int txId = currentProgram.startTransaction("Rename Structure Field");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dataType = dtm.getDataType("/" + structureName);
            if (dataType == null) {
                dataType = dtm.getDataType("/auto_structs/" + structureName);
            }

            if (dataType == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found")
                    .build();
            } else if (!(dataType instanceof Structure)) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Data type '" + structureName + "' found but is not a structure")
                    .build();
            }

            Structure structure = (Structure) dataType;
            DataTypeComponent component = null;
            if (offsetNum != null) {
                int offset = offsetNum.intValue();
                if (offset < 0 || offset >= structure.getLength()) {
                     return McpSchema.CallToolResult.builder()
                        .addTextContent("Offset " + offset + " is out of bounds for structure '" + structureName + "' (length " + structure.getLength() + ")")
                        .build();
                }
                component = structure.getComponentAt(offset);
                if (component == null) {
                     return McpSchema.CallToolResult.builder()
                        .addTextContent("No component found at offset " + offset + " in structure '" + structureName + "'")
                        .build();
                }
            } else {
                // Find by name
                DataTypeComponent[] components = structure.getComponents();
                for (DataTypeComponent c : components) {
                    String name = c.getFieldName();
                    if (name != null && name.equals(oldFieldName)) {
                        component = c;
                        break;
                    }
                }
                if (component == null) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Field '" + oldFieldName + "' not found in structure '" + structureName + "'")
                        .build();
                }
            }

            String previousName = component.getFieldName();
            try {
                component.setFieldName(newFieldName);
            } catch (Exception e) {
                 return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to set field name: " + e.getMessage())
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully renamed field in structure '" + structure.getName() + "': " +
                                (previousName != null ? previousName : ("offset " + component.getOffset())) +
                                " -> " + newFieldName)
                .build();

        } catch (Exception e) {
            String msg = "Error renaming structure field: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }
}
