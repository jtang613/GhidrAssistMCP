/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that returns detailed class member information including methods, fields, vtables, and virtual functions.
 */
public class GetClassInfoTool implements McpTool {
    
    /**
     * Inner class representing a class member with detailed information.
     */
    public static class ClassMemberInfo {
        public enum MemberType {
            METHOD, FIELD, VTABLE, VFUNCTION, TYPEINFO, STATIC_FIELD, CONSTRUCTOR, DESTRUCTOR, OPERATOR
        }
        
        private String name;
        private String type;
        private MemberType memberType;
        private boolean isStatic;
        private boolean isPublic;
        private Address address;
        private int vtableOffset; // For virtual function entries
        private List<String> vtableFunctions; // For vtable entries
        
        public ClassMemberInfo(String name, String type, MemberType memberType, 
                              boolean isStatic, boolean isPublic, Address address) {
            this.name = name;
            this.type = type;
            this.memberType = memberType;
            this.isStatic = isStatic;
            this.isPublic = isPublic;
            this.address = address;
            this.vtableOffset = -1;
            this.vtableFunctions = new ArrayList<>();
        }
        
        // Additional constructor for vtable entries
        public ClassMemberInfo(String name, String type, MemberType memberType, 
                              boolean isStatic, boolean isPublic, Address address, int vtableOffset) {
            this(name, type, memberType, isStatic, isPublic, address);
            this.vtableOffset = vtableOffset;
        }
        
        // Constructor for vtable with function list
        public ClassMemberInfo(String name, String type, MemberType memberType, 
                              boolean isStatic, boolean isPublic, Address address, List<String> vtableFunctions) {
            this(name, type, memberType, isStatic, isPublic, address);
            this.vtableFunctions = new ArrayList<>(vtableFunctions);
        }
        
        // Getters
        public String getName() { return name; }
        public String getType() { return type; }
        public MemberType getMemberType() { return memberType; }
        public boolean isStatic() { return isStatic; }
        public boolean isPublic() { return isPublic; }
        public Address getAddress() { return address; }
        public int getVtableOffset() { return vtableOffset; }
        public List<String> getVtableFunctions() { return vtableFunctions; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%s %s%s %s %s", 
                isPublic ? "public" : "private",
                isStatic ? "static " : "",
                memberType.toString().toLowerCase(),
                type, 
                name));
            
            if (address != null) {
                sb.append(" @ ").append(address);
            }
            
            if (vtableOffset >= 0) {
                sb.append(String.format(" [vtable+0x%x]", vtableOffset));
            }
            
            // Add vtable function pointers if this is a vtable
            if (memberType == MemberType.VTABLE && vtableFunctions != null && !vtableFunctions.isEmpty()) {
                sb.append(" -> ");
                for (int i = 0; i < vtableFunctions.size(); i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(String.format("vtable[%d]->%s", i, vtableFunctions.get(i)));
                }
            }
            
            return sb.toString();
        }
    }
    
    @Override
    public String getName() {
        return "get_class_info";
    }
    
    @Override
    public String getDescription() {
        return "Get detailed information about class members including methods, fields, vtables, and virtual functions";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "class_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("class_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }
        
        String className = (String) arguments.get("class_name");
        if (className == null || className.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("class_name parameter is required")
                .build();
        }
        
        // Get class members
        Map<String, List<ClassMemberInfo>> members = getClassMembers(className, currentProgram);
        
        // Format results
        String result = formatClassMembers(className, members);
        
        return McpSchema.CallToolResult.builder()
            .addTextContent(result)
            .build();
    }
    
    private Map<String, List<ClassMemberInfo>> getClassMembers(String className, Program program) {
        Map<String, List<ClassMemberInfo>> members = new HashMap<>();
        members.put("methods", new ArrayList<>());
        members.put("fields", new ArrayList<>());
        members.put("vtables", new ArrayList<>());
        members.put("virtual_functions", new ArrayList<>());
        members.put("typeinfo", new ArrayList<>());
        members.put("static_members", new ArrayList<>());
        
        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();
        
        // Find the class namespace
        Namespace classNamespace = findClassNamespace(className, program);
        if (classNamespace != null) {
            // Get all symbols in this class namespace
            List<Symbol> classSymbols = getSymbolsInNamespace(classNamespace, symbolTable);
            
            for (Symbol symbol : classSymbols) {
                analyzeSymbol(symbol, className, members, listing, program);
            }
        }
        
        // Look for vtables and related structures by pattern matching
        findVTablesAndTypeInfo(className, members, symbolTable, listing, program);
        
        // Extract virtual functions from vtables
        extractVirtualFunctions(members, listing, program);
        
        // Sort all categories
        for (List<ClassMemberInfo> memberList : members.values()) {
            memberList.sort(Comparator.comparing(ClassMemberInfo::getName));
        }
        
        return members;
    }
    
    private Namespace findClassNamespace(String className, Program program) {
        // First, get all class names using our robust search
        Set<String> allClassNames = getAllClassNames(program);
        
        // Find exact or partial matches
        String targetClassName = null;
        for (String foundClassName : allClassNames) {
            // Try exact match first
            if (foundClassName.equals(className)) {
                targetClassName = foundClassName;
                break;
            }
            // Try partial match (last component)
            String[] parts = foundClassName.split("::");
            if (parts.length > 0 && parts[parts.length - 1].equals(className)) {
                targetClassName = foundClassName;
                break;
            }
        }
        
        if (targetClassName == null) {
            // Try case-insensitive search
            for (String foundClassName : allClassNames) {
                if (foundClassName.toLowerCase().equals(className.toLowerCase())) {
                    targetClassName = foundClassName;
                    break;
                }
                String[] parts = foundClassName.split("::");
                if (parts.length > 0 && parts[parts.length - 1].toLowerCase().equals(className.toLowerCase())) {
                    targetClassName = foundClassName;
                    break;
                }
            }
        }
        
        if (targetClassName == null) {
            return null;
        }
        
        // Now find the namespace for this class name
        return findNamespaceForClassName(targetClassName, program);
    }
    
    private Namespace findNamespaceForClassName(String className, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        
        try {
            // Method 1: Direct class symbol lookup
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    if (symbol.getName().equals(className) || symbol.getName(true).equals(className)) {
                        Object obj = symbol.getObject();
                        if (obj instanceof Namespace) {
                            return (Namespace) obj;
                        }
                    }
                }
            }
            
            // Method 2: Look for symbols in namespaces that match the class name
            symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    if (ns.getName().equals(className) || ns.getName(true).equals(className)) {
                        // Check if this namespace represents a class
                        if (ns.getSymbol().getSymbolType() == SymbolType.CLASS) {
                            return ns;
                        }
                    }
                }
            }
            
            // Method 3: Look for class-related symbols (constructors, destructors, etc.)
            symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                String symbolName = symbol.getName();
                
                // Check for constructor/destructor patterns
                if (symbolName.contains("::") && symbolName.contains(className)) {
                    if (symbolName.contains("ctor") || symbolName.contains("dtor") || 
                        symbolName.matches(".*::" + className + "::.*")) {
                        
                        Namespace ns = symbol.getParentNamespace();
                        if (ns != null && !ns.isGlobal() && 
                            (ns.getName().equals(className) || ns.getName(true).contains(className))) {
                            return ns;
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Continue to return null
        }
        
        return null;
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
    
    private List<String> parseVTableFunctions(Symbol vtableSymbol, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();
        Address vtableAddr = vtableSymbol.getAddress();
        
        if (vtableAddr == null) {
            return functions;
        }
        
        try {
            // Try parsing as structured data first
            Data vtableData = listing.getDataAt(vtableAddr);
            if (vtableData != null) {
                functions.addAll(parseVTableEntriesForDisplay(vtableData, listing, program));
            } else {
                // Manually parse if no data structure is defined
                functions.addAll(parseVTableManuallyForDisplay(vtableAddr, listing, program));
            }
        } catch (Exception e) {
            // If parsing fails, try manual approach
            try {
                functions.addAll(parseVTableManuallyForDisplay(vtableAddr, listing, program));
            } catch (Exception e2) {
                // Return empty list if all parsing fails
            }
        }
        
        return functions;
    }
    
    private List<String> parseVTableEntriesForDisplay(Data vtableData, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();
        
        DataType dataType = vtableData.getDataType();
        if (dataType instanceof Array) {
            Array arrayType = (Array) dataType;
            int numElements = arrayType.getNumElements();
            
            for (int i = 0; i < numElements; i++) {
                Data elementData = vtableData.getComponent(i);
                if (elementData != null) {
                    Address functionAddr = getFunctionAddressFromPointer(elementData, program);
                    if (functionAddr != null) {
                        Function virtualFunction = listing.getFunctionAt(functionAddr);
                        if (virtualFunction != null) {
                            functions.add(virtualFunction.getName());
                        } else {
                            functions.add("FUN_" + functionAddr.toString().replace(":", ""));
                        }
                    }
                }
            }
        }
        
        return functions;
    }
    
    private List<String> parseVTableManuallyForDisplay(Address vtableAddr, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();
        
        int pointerSize = program.getDefaultPointerSize();
        Address currentAddr = vtableAddr;
        
        // Try to read up to 50 potential function pointers
        for (int i = 0; i < 50; i++) {
            try {
                Data pointerData = listing.getDataAt(currentAddr);
                Address functionAddr = null;
                
                if (pointerData != null && pointerData.getDataType() instanceof Pointer) {
                    functionAddr = getFunctionAddressFromPointer(pointerData, program);
                } else {
                    // Try to read as raw pointer
                    long pointerValue = program.getMemory().getLong(currentAddr);
                    if (pointerValue != 0) {
                        try {
                            functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                        } catch (Exception e) {
                            // Invalid address, break
                            break;
                        }
                    }
                }
                
                if (functionAddr != null) {
                    Function virtualFunction = listing.getFunctionAt(functionAddr);
                    if (virtualFunction != null) {
                        functions.add(virtualFunction.getName());
                    } else {
                        // Check if it's a valid code address
                        if (program.getMemory().contains(functionAddr)) {
                            functions.add("FUN_" + functionAddr.toString().replace(":", ""));
                        } else {
                            // Not a valid function address, probably reached end of vtable
                            break;
                        }
                    }
                } else {
                    // If we hit a null pointer, we've likely reached the end
                    break;
                }
                
                currentAddr = currentAddr.add(pointerSize);
                
            } catch (Exception e) {
                // Memory read error, probably reached end of vtable
                break;
            }
        }
        
        return functions;
    }
    
    private List<Symbol> getSymbolsInNamespace(Namespace namespace, SymbolTable symbolTable) {
        List<Symbol> symbols = new ArrayList<>();
        
        try {
            SymbolIterator symbolIter = symbolTable.getSymbols(namespace);
            while (symbolIter.hasNext()) {
                symbols.add(symbolIter.next());
            }
        } catch (Exception e) {
            // Return empty list if namespace traversal fails
        }
        
        return symbols;
    }
    
    private void analyzeSymbol(Symbol symbol, String className, 
                              Map<String, List<ClassMemberInfo>> members, 
                              Listing listing, Program program) {
        String symbolName = symbol.getName();
        SymbolType symbolType = symbol.getSymbolType();
        Address address = symbol.getAddress();
        
        // Check for vtable first
        if (isVTable(symbol, className)) {
            List<String> vtableFunctions = parseVTableFunctions(symbol, listing, program);
            ClassMemberInfo vtable = new ClassMemberInfo(
                symbolName, "vtable", ClassMemberInfo.MemberType.VTABLE, 
                true, false, address, vtableFunctions);
            members.get("vtables").add(vtable);
            return;
        }
        
        // Check for typeinfo/RTTI
        if (isTypeInfo(symbol, className)) {
            ClassMemberInfo typeinfo = new ClassMemberInfo(
                symbolName, "typeinfo", ClassMemberInfo.MemberType.TYPEINFO, 
                true, false, address);
            members.get("typeinfo").add(typeinfo);
            return;
        }
        
        if (symbolType == SymbolType.FUNCTION) {
            ClassMemberInfo method = createMethodInfo(symbol, listing);
            if (method != null) {
                members.get("methods").add(method);
            }
        } else if (symbolType == SymbolType.GLOBAL) {
            // Static member variable
            ClassMemberInfo staticMember = createStaticMemberInfo(symbol, listing);
            if (staticMember != null) {
                members.get("static_members").add(staticMember);
            }
        } else if (symbolType == SymbolType.LOCAL_VAR || symbolType == SymbolType.PARAMETER) {
            ClassMemberInfo field = createFieldInfo(symbol, listing);
            if (field != null) {
                members.get("fields").add(field);
            }
        } else if (symbolType == SymbolType.LABEL) {
            analyzeLabel(symbol, className, members, listing);
        } else {
            // Other symbol types - try to categorize generically
            ClassMemberInfo generic = createGenericMemberInfo(symbol, listing);
            if (generic != null) {
                members.get("fields").add(generic);
            }
        }
    }
    
    private boolean isVTable(Symbol symbol, String className) {
        String name = symbol.getName().toLowerCase();
        String classLower = className.toLowerCase();
        
        // Common vtable patterns
        return name.contains("vtable") || 
               name.contains("vftable") ||  // MSVC vftable
               name.contains("_ztv") ||  // GCC mangled vtable
               name.contains("_7" + classLower) || // Some MSVC patterns
               (name.contains(classLower) && name.contains("vft")) || // MSVC vftable
               name.matches(".*vtbl.*") ||
               name.matches(".*::" + classLower + "::.*vtable.*") ||
               name.matches(".*::" + classLower + "::.*vftable.*") ||
               // Match exact patterns like "ClassName::vftable"
               name.equals(classLower + "::vftable") ||
               name.endsWith("::vftable") ||
               name.endsWith("::vtable");
    }
    
    private boolean isTypeInfo(Symbol symbol, String className) {
        String name = symbol.getName().toLowerCase();
        String classLower = className.toLowerCase();
        
        // Common typeinfo/RTTI patterns
        return name.contains("typeinfo") ||
               name.contains("_zti") ||  // GCC mangled typeinfo
               name.contains("_rti") ||  // Some RTTI patterns
               name.contains("class_type_info") ||
               (name.contains(classLower) && (name.contains("rtti") || name.contains("type")));
    }
    
    private ClassMemberInfo createMethodInfo(Symbol symbol, Listing listing) {
        String methodName = symbol.getName();
        String returnType = "unknown";
        ClassMemberInfo.MemberType memberType = ClassMemberInfo.MemberType.METHOD;
        
        Function function = listing.getFunctionAt(symbol.getAddress());
        if (function != null && function.getSignature() != null) {
            returnType = function.getSignature().getReturnType().getDisplayName();
        }
        
        // Determine method type
        if (methodName.contains("ctor") || methodName.contains("constructor")) {
            memberType = ClassMemberInfo.MemberType.CONSTRUCTOR;
        } else if (methodName.contains("dtor") || methodName.contains("destructor") || methodName.startsWith("~")) {
            memberType = ClassMemberInfo.MemberType.DESTRUCTOR;
        } else if (methodName.contains("operator")) {
            memberType = ClassMemberInfo.MemberType.OPERATOR;
        }
        
        return new ClassMemberInfo(methodName, returnType, memberType, 
                                  false, true, symbol.getAddress());
    }
    
    private ClassMemberInfo createFieldInfo(Symbol symbol, Listing listing) {
        String fieldName = symbol.getName();
        String fieldType = "unknown";
        
        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            fieldType = data.getDataType().getDisplayName();
        }
        
        return new ClassMemberInfo(fieldName, fieldType, ClassMemberInfo.MemberType.FIELD, 
                                  false, true, symbol.getAddress());
    }
    
    private ClassMemberInfo createStaticMemberInfo(Symbol symbol, Listing listing) {
        String fieldName = symbol.getName();
        String fieldType = "unknown";
        
        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            fieldType = data.getDataType().getDisplayName();
        }
        
        return new ClassMemberInfo(fieldName, fieldType, ClassMemberInfo.MemberType.STATIC_FIELD, 
                                  true, true, symbol.getAddress());
    }
    
    private ClassMemberInfo createGenericMemberInfo(Symbol symbol, Listing listing) {
        String memberName = symbol.getName();
        String memberType = "unknown";
        
        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            memberType = data.getDataType().getDisplayName();
        }
        
        return new ClassMemberInfo(memberName, memberType, ClassMemberInfo.MemberType.FIELD, 
                                  false, true, symbol.getAddress());
    }
    
    private void analyzeLabel(Symbol symbol, String className, 
                             Map<String, List<ClassMemberInfo>> members, Listing listing) {
        
        // Skip if already categorized as vtable or typeinfo
        if (isVTable(symbol, className) || isTypeInfo(symbol, className)) {
            return;
        }
        
        ClassMemberInfo labelMember = createGenericMemberInfo(symbol, listing);
        if (labelMember != null) {
            if (isLikelyMethod(symbol, listing)) {
                labelMember = new ClassMemberInfo(labelMember.getName(), labelMember.getType(), 
                                                 ClassMemberInfo.MemberType.METHOD,
                                                 labelMember.isStatic(), labelMember.isPublic(), 
                                                 labelMember.getAddress());
                members.get("methods").add(labelMember);
            } else {
                members.get("fields").add(labelMember);
            }
        }
    }
    
    private boolean isLikelyMethod(Symbol symbol, Listing listing) {
        // Check if there's a function at this address
        Function function = listing.getFunctionAt(symbol.getAddress());
        return function != null;
    }
    
    private void findVTablesAndTypeInfo(String className, Map<String, List<ClassMemberInfo>> members,
                                       SymbolTable symbolTable, Listing listing, Program program) {
        
        // Search for vtable patterns across the entire symbol table
        String[] vtablePatterns = {
            "*vtable*" + className + "*",
            "*" + className + "*vtable*",
            "_ZTV*" + className + "*",  // GCC mangled
            "*" + className + "*vft*"   // MSVC
        };
        
        for (String pattern : vtablePatterns) {
            try {
                SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
                while (allSymbols.hasNext()) {
                    Symbol symbol = allSymbols.next();
                    String symbolNameLower = symbol.getName().toLowerCase();
                    String classNameLower = className.toLowerCase();
                    if ((symbolNameLower.contains("vtable") || symbolNameLower.contains("vftable")) && 
                        symbolNameLower.contains(classNameLower)) {
                        if (isVTable(symbol, className)) {
                            List<String> vtableFunctions = parseVTableFunctions(symbol, listing, program);
                            ClassMemberInfo vtable = new ClassMemberInfo(
                                symbol.getName(), "vtable", ClassMemberInfo.MemberType.VTABLE,
                                true, false, symbol.getAddress(), vtableFunctions);
                            members.get("vtables").add(vtable);
                        }
                    }
                }
            } catch (Exception e) {
                // Continue with next pattern
            }
        }
        
        // Search for typeinfo patterns
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                if (symbol.getName().toLowerCase().contains("typeinfo") && 
                    symbol.getName().toLowerCase().contains(className.toLowerCase())) {
                    if (isTypeInfo(symbol, className)) {
                        ClassMemberInfo typeinfo = new ClassMemberInfo(
                            symbol.getName(), "typeinfo", ClassMemberInfo.MemberType.TYPEINFO,
                            true, false, symbol.getAddress());
                        members.get("typeinfo").add(typeinfo);
                    }
                }
            }
        } catch (Exception e) {
            // Continue if search fails
        }
    }
    
    private void extractVirtualFunctions(Map<String, List<ClassMemberInfo>> members, 
                                       Listing listing, Program program) {
        
        for (ClassMemberInfo vtable : members.get("vtables")) {
            Address vtableAddr = vtable.getAddress();
            
            // Parse the vtable to extract virtual function pointers
            Data vtableData = listing.getDataAt(vtableAddr);
            if (vtableData != null) {
                parseVTableEntries(vtableData, members.get("virtual_functions"), listing, program);
            } else {
                // Manually parse if no data structure is defined
                parseVTableManually(vtableAddr, members.get("virtual_functions"), listing, program);
            }
        }
    }
    
    private void parseVTableEntries(Data vtableData, List<ClassMemberInfo> virtualFunctions, 
                                   Listing listing, Program program) {
        
        DataType dataType = vtableData.getDataType();
        if (dataType instanceof Array) {
            Array arrayType = (Array) dataType;
            int numElements = arrayType.getNumElements();
            
            for (int i = 0; i < numElements; i++) {
                Data elementData = vtableData.getComponent(i);
                if (elementData != null) {
                    Address functionAddr = getFunctionAddressFromPointer(elementData, program);
                    if (functionAddr != null) {
                        Function virtualFunction = listing.getFunctionAt(functionAddr);
                        if (virtualFunction != null) {
                            ClassMemberInfo vfunc = new ClassMemberInfo(
                                virtualFunction.getName(), 
                                virtualFunction.getSignature() != null ? 
                                    virtualFunction.getSignature().getReturnType().getDisplayName() : "unknown",
                                ClassMemberInfo.MemberType.VFUNCTION,
                                false, true, functionAddr, i * program.getDefaultPointerSize());
                            virtualFunctions.add(vfunc);
                        }
                    }
                }
            }
        }
    }
    
    private void parseVTableManually(Address vtableAddr, List<ClassMemberInfo> virtualFunctions,
                                    Listing listing, Program program) {
        
        int pointerSize = program.getDefaultPointerSize();
        Address currentAddr = vtableAddr;
        int offset = 0;
        
        // Try to read up to 50 potential function pointers
        for (int i = 0; i < 50; i++) {
            try {
                Data pointerData = listing.getDataAt(currentAddr);
                Address functionAddr = null;
                
                if (pointerData != null && pointerData.getDataType() instanceof Pointer) {
                    functionAddr = getFunctionAddressFromPointer(pointerData, program);
                } else {
                    // Try to read as raw pointer
                    long pointerValue = program.getMemory().getLong(currentAddr);
                    if (pointerValue != 0) {
                        functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                    }
                }
                
                if (functionAddr != null) {
                    Function virtualFunction = listing.getFunctionAt(functionAddr);
                    if (virtualFunction != null) {
                        ClassMemberInfo vfunc = new ClassMemberInfo(
                            virtualFunction.getName(), 
                            virtualFunction.getSignature() != null ? 
                                virtualFunction.getSignature().getReturnType().getDisplayName() : "unknown",
                            ClassMemberInfo.MemberType.VFUNCTION,
                            false, true, functionAddr, offset);
                        virtualFunctions.add(vfunc);
                    }
                } else {
                    // If we hit a null pointer or invalid address, we've likely reached the end
                    break;
                }
                
                currentAddr = currentAddr.add(pointerSize);
                offset += pointerSize;
                
            } catch (Exception e) {
                // Memory read error, probably reached end of vtable
                break;
            }
        }
    }
    
    private Address getFunctionAddressFromPointer(Data pointerData, Program program) {
        if (pointerData.getDataType() instanceof Pointer) {
            Object value = pointerData.getValue();
            if (value instanceof Address) {
                return (Address) value;
            }
        }
        return null;
    }
    
    private String formatClassMembers(String className, Map<String, List<ClassMemberInfo>> members) {
        StringBuilder result = new StringBuilder();
        result.append("Class: ").append(className).append("\n\n");
        
        // Methods
        if (!members.get("methods").isEmpty()) {
            result.append("Methods (").append(members.get("methods").size()).append("):\n");
            for (ClassMemberInfo method : members.get("methods")) {
                result.append("  ").append(method.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // Fields
        if (!members.get("fields").isEmpty()) {
            result.append("Fields (").append(members.get("fields").size()).append("):\n");
            for (ClassMemberInfo field : members.get("fields")) {
                result.append("  ").append(field.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // VTables
        if (!members.get("vtables").isEmpty()) {
            result.append("VTables (").append(members.get("vtables").size()).append("):\n");
            for (ClassMemberInfo vtable : members.get("vtables")) {
                result.append("  ").append(vtable.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // Virtual Functions
        if (!members.get("virtual_functions").isEmpty()) {
            result.append("Virtual Functions (").append(members.get("virtual_functions").size()).append("):\n");
            for (ClassMemberInfo vfunc : members.get("virtual_functions")) {
                result.append("  ").append(vfunc.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // Static Members
        if (!members.get("static_members").isEmpty()) {
            result.append("Static Members (").append(members.get("static_members").size()).append("):\n");
            for (ClassMemberInfo staticMember : members.get("static_members")) {
                result.append("  ").append(staticMember.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // Type Info
        if (!members.get("typeinfo").isEmpty()) {
            result.append("Type Info (").append(members.get("typeinfo").size()).append("):\n");
            for (ClassMemberInfo typeinfo : members.get("typeinfo")) {
                result.append("  ").append(typeinfo.toString()).append("\n");
            }
            result.append("\n");
        }
        
        // Summary
        int totalMembers = members.values().stream().mapToInt(List::size).sum();
        if (totalMembers == 0) {
            result.append("No class members found for class: ").append(className);
        } else {
            result.append("Total members found: ").append(totalMembers);
        }

        return result.toString();
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }
}