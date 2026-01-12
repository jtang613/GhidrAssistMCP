/*
 * MCP tool for finding cross-references to struct fields
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that finds cross-references to specific struct fields.
 * Supports both type-based queries (all instances of a struct type) and
 * instance-based queries (specific struct instance at a known address).
 */
public class StructFieldXrefsTool implements McpTool {

    /**
     * Inner class to hold field reference results
     */
    private static class FieldReference {
        Address address;
        String functionName;
        Address functionAddress;
        String accessType;  // "READ", "WRITE", "UNKNOWN"
        String context;     // Decompiled line or description
        String source;      // "DECOMPILER" or "ADDRESS"

        FieldReference(Address address, String functionName, Address functionAddress,
                      String accessType, String context, String source) {
            this.address = address;
            this.functionName = functionName;
            this.functionAddress = functionAddress;
            this.accessType = accessType;
            this.context = context;
            this.source = source;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s: %s", accessType, address, context);
        }
    }

    @Override
    public String getName() {
        return "struct_field_xrefs";
    }

    @Override
    public String getDescription() {
        return "Find cross-references to a specific struct field. " +
               "Supports type-based queries (all instances) and instance-based queries (specific address). " +
               "Examples: " +
               "1) Type-based: {\"struct_name\": \"Host\", \"field_name\": \"port\"} " +
               "2) Instance-based: {\"struct_name\": \"Host\", \"field_name\": \"port\", \"instance_address\": \"0x401000\"} " +
               "3) By offset: {\"struct_name\": \"Host\", \"field_offset\": 4}";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "struct_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "field_offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "instance_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("struct_name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Parse required parameters
        String structName = (String) arguments.get("struct_name");
        if (structName == null || structName.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("struct_name parameter is required")
                .build();
        }

        // Parse optional field identifiers
        String fieldName = (String) arguments.get("field_name");
        Integer fieldOffset = null;
        if (arguments.get("field_offset") instanceof Number) {
            fieldOffset = ((Number) arguments.get("field_offset")).intValue();
        }

        if ((fieldName == null || fieldName.trim().isEmpty()) && fieldOffset == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either field_name or field_offset parameter is required")
                .build();
        }

        // Parse optional instance address
        String instanceAddressStr = (String) arguments.get("instance_address");
        Address instanceAddress = null;
        if (instanceAddressStr != null && !instanceAddressStr.trim().isEmpty()) {
            try {
                instanceAddress = currentProgram.getAddressFactory().getAddress(instanceAddressStr);
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid instance_address format: " + instanceAddressStr)
                    .build();
            }
        }

        // Parse pagination
        int offset = 0;
        int limit = 100;
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        // Resolve structure
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = resolveStructure(dtm, structName);
        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structName)
                .build();
        }

        // Resolve field
        DataTypeComponent fieldComponent = resolveField(struct, fieldName, fieldOffset);
        if (fieldComponent == null) {
            String fieldDesc = fieldName != null ? "field_name: " + fieldName : "field_offset: " + fieldOffset;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Field not found in structure " + struct.getName() + " with " + fieldDesc)
                .build();
        }

        int resolvedFieldOffset = fieldComponent.getOffset();
        int fieldSize = fieldComponent.getLength();
        String resolvedFieldName = fieldComponent.getFieldName() != null ?
            fieldComponent.getFieldName() : "(offset_" + resolvedFieldOffset + ")";

        // Build result
        StringBuilder result = new StringBuilder();
        result.append("Struct Field Cross-References for ")
              .append(struct.getName()).append(".").append(resolvedFieldName)
              .append(" (offset +0x").append(String.format("%X", resolvedFieldOffset))
              .append(", ").append(fieldSize).append(" bytes):\n\n");

        List<FieldReference> allReferences = new ArrayList<>();

        // Run type-based query (decompiler analysis)
        List<FieldReference> typeBasedRefs = findTypeBasedReferences(
            currentProgram, struct, resolvedFieldName, resolvedFieldOffset);

        if (!typeBasedRefs.isEmpty()) {
            result.append("=== Type-Based References ===\n");
            allReferences.addAll(typeBasedRefs);
        }

        // Run instance-based query if address provided
        if (instanceAddress != null) {
            List<FieldReference> instanceRefs = findInstanceBasedReferences(
                currentProgram, instanceAddress, resolvedFieldOffset, fieldSize);

            if (!instanceRefs.isEmpty()) {
                result.append("\n=== Instance-Based References (at ")
                      .append(instanceAddress).append(") ===\n");
                allReferences.addAll(instanceRefs);
            }
        }

        // Format and paginate results
        if (allReferences.isEmpty()) {
            result.append("No references found.\n");
        } else {
            // Group by function for type-based results
            String currentFunction = null;
            int displayCount = 0;
            int totalCount = allReferences.size();

            for (int i = 0; i < allReferences.size(); i++) {
                if (i < offset) continue;
                if (displayCount >= limit) break;

                FieldReference ref = allReferences.get(i);

                // Print function header for new functions
                if (ref.source.equals("DECOMPILER") &&
                    (currentFunction == null || !currentFunction.equals(ref.functionName))) {
                    currentFunction = ref.functionName;
                    result.append("\nFunction: ").append(ref.functionName);
                    if (ref.functionAddress != null) {
                        result.append(" (").append(ref.functionAddress).append(")");
                    }
                    result.append("\n");
                }

                result.append("  ").append(ref.toString()).append("\n");
                displayCount++;
            }

            result.append("\nShowing ").append(displayCount).append(" of ")
                  .append(totalCount).append(" references");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
            result.append("\n");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Find type-based references using decompiler analysis.
     * Iterates all functions, decompiles them, and walks the token tree for ClangFieldToken.
     */
    private List<FieldReference> findTypeBasedReferences(
            Program program,
            Structure targetStruct,
            String targetFieldName,
            int targetFieldOffset) {

        List<FieldReference> references = new ArrayList<>();

        DecompInterface decompiler = new DecompInterface();
        try {
            // Setup decompiler
            DecompileOptions options = new DecompileOptions();
            options.grabFromProgram(program);
            decompiler.setOptions(options);
            decompiler.openProgram(program);

            // Iterate all functions
            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                Function function = funcIter.next();

                // Skip external/thunk functions
                if (function.isExternal() || function.isThunk()) {
                    continue;
                }

                try {
                    // Decompile with timeout
                    DecompileResults results = decompiler.decompileFunction(
                        function, 30, TaskMonitor.DUMMY);

                    if (!results.decompileCompleted()) {
                        continue;
                    }

                    ClangTokenGroup tokenGroup = results.getCCodeMarkup();
                    if (tokenGroup == null) {
                        continue;
                    }

                    // Walk token tree looking for field accesses
                    walkClangTokens(tokenGroup, targetStruct, targetFieldOffset,
                        function.getName(), function.getEntryPoint(), references);

                } catch (Exception e) {
                    // Skip functions that fail to decompile
                    continue;
                }
            }
        } finally {
            decompiler.dispose();
        }

        return references;
    }

    /**
     * Recursively walk the Clang token tree looking for ClangFieldToken nodes
     * that match the target structure and field offset.
     */
    private void walkClangTokens(
            ClangNode node,
            Structure targetStruct,
            int targetFieldOffset,
            String functionName,
            Address functionAddress,
            List<FieldReference> results) {

        if (node instanceof ClangFieldToken) {
            ClangFieldToken fieldToken = (ClangFieldToken) node;

            // Get the data type this field belongs to
            DataType parentType = fieldToken.getDataType();
            int fieldOffset = fieldToken.getOffset();

            // Check if this matches our target
            if (isMatchingStructType(parentType, targetStruct) &&
                fieldOffset == targetFieldOffset) {

                // Determine access type from context
                String accessType = determineAccessType(fieldToken);

                // Get the address where this access occurs
                Address minAddress = fieldToken.getMinAddress();

                // Get context (the field access text)
                String context = fieldToken.toString();

                results.add(new FieldReference(
                    minAddress,
                    functionName,
                    functionAddress,
                    accessType,
                    context,
                    "DECOMPILER"
                ));
            }
        }

        // Recursively process children
        int numChildren = node.numChildren();
        for (int i = 0; i < numChildren; i++) {
            walkClangTokens(node.Child(i), targetStruct, targetFieldOffset,
                functionName, functionAddress, results);
        }
    }

    /**
     * Check if a data type matches the target structure.
     * Handles TypeDef unwrapping and pointer dereferencing.
     */
    private boolean isMatchingStructType(DataType type, Structure targetStruct) {
        if (type == null) {
            return false;
        }

        // Unwrap TypeDef
        while (type instanceof TypeDef) {
            type = ((TypeDef) type).getBaseDataType();
        }

        // Check direct match
        if (type instanceof Structure) {
            Structure s = (Structure) type;
            // Match by name (could also match by UUID for more accuracy)
            return s.getName().equals(targetStruct.getName());
        }

        return false;
    }

    /**
     * Try to determine if a field access is a read or write.
     * This is a heuristic based on the token's position in the syntax tree.
     */
    private String determineAccessType(ClangFieldToken fieldToken) {
        // Look at parent nodes to determine if this is an lvalue (write) or rvalue (read)
        ClangNode parent = fieldToken.Parent();

        if (parent != null) {
            String parentText = parent.toString();
            // Simple heuristic: if field is on left side of assignment, it's a write
            if (parentText.contains("=") && !parentText.contains("==")) {
                String fieldText = fieldToken.toString();
                int equalPos = parentText.indexOf('=');
                int fieldPos = parentText.indexOf(fieldText);
                if (fieldPos >= 0 && fieldPos < equalPos) {
                    return "WRITE";
                }
            }
        }

        return "READ";
    }

    /**
     * Find instance-based references using ReferenceManager.
     * Calculates the field's memory address and finds all references to it.
     */
    private List<FieldReference> findInstanceBasedReferences(
            Program program,
            Address baseAddress,
            int fieldOffset,
            int fieldSize) {

        List<FieldReference> references = new ArrayList<>();

        // Calculate field address
        Address fieldAddress = baseAddress.add(fieldOffset);

        // Get references to the field address (and adjacent bytes for multi-byte fields)
        for (int byteOffset = 0; byteOffset < fieldSize; byteOffset++) {
            Address targetAddr = fieldAddress.add(byteOffset);
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(targetAddr);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                // Determine access type
                String accessType = classifyReferenceType(refType);

                // Get containing function
                Function containingFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcName = containingFunc != null ? containingFunc.getName() : "(unknown)";
                Address funcAddr = containingFunc != null ? containingFunc.getEntryPoint() : null;

                // Get instruction/data at reference
                String context = refType.toString() + " at " + fromAddr;

                // Avoid duplicate entries for multi-byte fields
                boolean isDuplicate = references.stream()
                    .anyMatch(r -> r.address.equals(fromAddr) && r.source.equals("ADDRESS"));

                if (!isDuplicate) {
                    references.add(new FieldReference(
                        fromAddr,
                        funcName,
                        funcAddr,
                        accessType,
                        context,
                        "ADDRESS"
                    ));
                }
            }
        }

        return references;
    }

    /**
     * Classify a reference type as READ, WRITE, or UNKNOWN.
     */
    private String classifyReferenceType(RefType refType) {
        if (refType.isRead()) {
            return "READ";
        } else if (refType.isWrite()) {
            return "WRITE";
        } else if (refType.isData()) {
            return "DATA";
        } else if (refType.isCall()) {
            return "CALL";
        }
        return "UNKNOWN";
    }

    /**
     * Resolve a structure by name from the DataTypeManager.
     * Tries multiple lookup strategies.
     */
    private Structure resolveStructure(DataTypeManager dtm, String structName) {
        // Try direct lookup
        DataType dt = dtm.getDataType("/" + structName);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }

        // Try without leading slash
        dt = dtm.getDataType(structName);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }

        // Search all data types
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();

            // Unwrap TypeDef
            DataType baseType = dataType;
            while (baseType instanceof TypeDef) {
                baseType = ((TypeDef) baseType).getBaseDataType();
            }

            if (baseType instanceof Structure) {
                Structure s = (Structure) baseType;
                // Match by name (case-sensitive first, then insensitive)
                if (s.getName().equals(structName)) {
                    return s;
                }
            }
        }

        // Try case-insensitive search
        iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            DataType baseType = dataType;
            while (baseType instanceof TypeDef) {
                baseType = ((TypeDef) baseType).getBaseDataType();
            }

            if (baseType instanceof Structure) {
                Structure s = (Structure) baseType;
                if (s.getName().equalsIgnoreCase(structName)) {
                    return s;
                }
            }
        }

        return null;
    }

    /**
     * Resolve a field within a structure by name or offset.
     */
    private DataTypeComponent resolveField(Structure struct, String fieldName, Integer fieldOffset) {
        DataTypeComponent[] components = struct.getComponents();

        // If offset is provided, use it directly
        if (fieldOffset != null) {
            DataTypeComponent comp = struct.getComponentAt(fieldOffset);
            if (comp != null) {
                return comp;
            }
            // Try exact offset match in components
            for (DataTypeComponent comp2 : components) {
                if (comp2.getOffset() == fieldOffset) {
                    return comp2;
                }
            }
            return null;
        }

        // Search by field name
        if (fieldName != null) {
            // Exact match first
            for (DataTypeComponent comp : components) {
                String compName = comp.getFieldName();
                if (compName != null && compName.equals(fieldName)) {
                    return comp;
                }
            }

            // Case-insensitive match
            for (DataTypeComponent comp : components) {
                String compName = comp.getFieldName();
                if (compName != null && compName.equalsIgnoreCase(fieldName)) {
                    return comp;
                }
            }
        }

        return null;
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}
