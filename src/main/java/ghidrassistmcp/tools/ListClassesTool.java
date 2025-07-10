/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists classes defined in the program.
 */
public class ListClassesTool implements McpTool {
    
    @Override
    public String getName() {
        return "list_classes";
    }
    
    @Override
    public String getDescription() {
        return "List classes defined in the program";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        // Get all class names using comprehensive approach
        Set<String> allClassNames = getAllClassNames(currentProgram);
        
        // Convert to sorted list
        List<String> sortedClasses = new ArrayList<>(allClassNames);
        Collections.sort(sortedClasses);
        
        StringBuilder result = new StringBuilder();
        result.append("Classes in program:\n\n");
        
        int totalCount = sortedClasses.size();
        int count = 0;
        
        for (int i = offset; i < sortedClasses.size() && count < limit; i++) {
            result.append("- ").append(sortedClasses.get(i)).append("\n");
            count++;
        }
        
        if (totalCount == 0) {
            result.append("No classes found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" classes");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
    
    private Set<String> getAllClassNames(Program program) {
        Set<String> classNames = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Method 1: Direct SymbolType.CLASS symbols
        try {
            SymbolIterator classSymbols = symbolTable.getAllSymbols(true);
            while (classSymbols.hasNext()) {
                Symbol symbol = classSymbols.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    classNames.add(symbol.getName(true)); // Full qualified name
                }
            }
        } catch (Exception e) {
            // Continue with other methods if this fails
        }
        
        // Method 2: Parent namespaces of all symbols
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    if (isLikelyClass(ns)) {
                        classNames.add(ns.getName(true));
                    }
                }
            }
        } catch (Exception e) {
            // Continue with other methods if this fails
        }
        
        // Method 3: Recursive namespace traversal for nested classes
        try {
            findClassesRecursively(program.getGlobalNamespace(), symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods if this fails
        }
        
        // Method 4: C++ mangled name heuristics
        try {
            findCppClassesFromMangledNames(symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods if this fails
        }
        
        // Method 5: Look for vtables (C++ specific)
        try {
            findClassesFromVTables(symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods if this fails
        }
        
        return classNames;
    }
    
    private boolean isLikelyClass(Namespace namespace) {
        SymbolType type = namespace.getSymbol().getSymbolType();
        
        // Explicit class types
        if (type == SymbolType.CLASS) {
            return true;
        }
        
        // Namespaces that might be classes
        if (type == SymbolType.NAMESPACE) {
            return true;
        }
        
        return false;
    }
    
    private void findClassesRecursively(Namespace namespace, SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator children = symbolTable.getSymbols(namespace);
            while (children.hasNext()) {
                Symbol symbol = children.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    classNames.add(symbol.getName(true));
                }
                
                if (symbol.getSymbolType() == SymbolType.NAMESPACE) {
                    Object obj = symbol.getObject();
                    if (obj instanceof Namespace) {
                        Namespace childNamespace = (Namespace) obj;
                        findClassesRecursively(childNamespace, symbolTable, classNames);
                    }
                }
            }
        } catch (Exception e) {
            // Skip if we can't traverse this namespace
        }
    }
    
    private void findCppClassesFromMangledNames(SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                String name = symbol.getName();
                
                // C++ constructor/destructor patterns
                if (name.contains("::")) {
                    if (name.contains("ctor") || name.contains("dtor") || 
                        name.matches(".*::[~]?\\w+\\(.*\\)")) {
                        
                        String className = extractClassNameFromMethod(name);
                        if (className != null && !className.isEmpty()) {
                            classNames.add(className);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Skip if symbol iteration fails
        }
    }
    
    private void findClassesFromVTables(SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                String name = symbol.getName();
                
                // Look for vtable symbols
                if (name.toLowerCase().contains("vtable") || name.toLowerCase().contains("vftable")) {
                    String className = extractClassNameFromVTable(name);
                    if (className != null && !className.isEmpty()) {
                        classNames.add(className);
                    }
                }
            }
        } catch (Exception e) {
            // Skip if symbol iteration fails
        }
    }
    
    private String extractClassNameFromMethod(String methodName) {
        int lastScope = methodName.lastIndexOf("::");
        if (lastScope > 0) {
            return methodName.substring(0, lastScope);
        }
        return null;
    }
    
    private String extractClassNameFromVTable(String vtableName) {
        // Handle "vtable for ClassName" pattern
        if (vtableName.startsWith("vtable for ")) {
            return vtableName.substring("vtable for ".length());
        }
        
        // Handle "vftable for ClassName" pattern
        if (vtableName.startsWith("vftable for ")) {
            return vtableName.substring("vftable for ".length());
        }
        
        // Handle "ClassName::vtable" pattern  
        if (vtableName.contains("::vtable")) {
            return vtableName.substring(0, vtableName.indexOf("::vtable"));
        }
        
        // Handle "ClassName::vftable" pattern  
        if (vtableName.contains("::vftable")) {
            return vtableName.substring(0, vtableName.indexOf("::vftable"));
        }
        
        return null;
    }
}