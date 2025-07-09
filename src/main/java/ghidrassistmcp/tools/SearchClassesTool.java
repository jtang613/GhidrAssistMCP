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
 * MCP tool that searches for classes/structures by name pattern.
 */
public class SearchClassesTool implements McpTool {
    
    @Override
    public String getName() {
        return "search_classes";
    }
    
    @Override
    public String getDescription() {
        return "Search for classes by name pattern (supports partial matching)";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "case_sensitive", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("pattern"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String pattern = (String) arguments.get("pattern");
        if (pattern == null || pattern.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("pattern parameter is required")
                .build();
        }
        
        // Parse optional parameters
        boolean caseSensitive = true;
        if (arguments.get("case_sensitive") instanceof Boolean) {
            caseSensitive = (Boolean) arguments.get("case_sensitive");
        }
        
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
        
        // Filter by pattern
        List<String> matchingClasses = new ArrayList<>();
        String searchPattern = caseSensitive ? pattern : pattern.toLowerCase();
        
        for (String className : allClassNames) {
            String nameToSearch = caseSensitive ? className : className.toLowerCase();
            if (nameToSearch.contains(searchPattern)) {
                matchingClasses.add(className);
            }
        }
        
        // Sort for consistent output
        Collections.sort(matchingClasses);
        
        StringBuilder result = new StringBuilder();
        result.append("Classes matching pattern: \"").append(pattern).append("\"");
        result.append(" (case ").append(caseSensitive ? "sensitive" : "insensitive").append(")\n\n");
        
        int totalCount = matchingClasses.size();
        int count = 0;
        
        for (int i = offset; i < matchingClasses.size() && count < limit; i++) {
            result.append("- ").append(matchingClasses.get(i)).append("\n");
            count++;
        }
        
        if (totalCount == 0) {
            result.append("No classes found matching pattern: \"").append(pattern).append("\"");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" matching classes");
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
                if (name.toLowerCase().contains("vtable")) {
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
        
        // Handle "ClassName::vtable" pattern  
        if (vtableName.contains("::vtable")) {
            return vtableName.substring(0, vtableName.indexOf("::vtable"));
        }
        
        return null;
    }
}