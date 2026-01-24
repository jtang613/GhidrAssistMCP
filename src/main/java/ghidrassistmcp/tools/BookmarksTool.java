/*
 * MCP tool for managing bookmarks.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for listing, adding, and deleting bookmarks.
 */
public class BookmarksTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        // May modify program when adding/deleting bookmarks
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "bookmarks";
    }

    @Override
    public String getDescription() {
        return "Manage bookmarks: list, add, or delete bookmarks at addresses";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "category", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "type", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Action is required: 'list', 'add', or 'delete'")
                .build();
        }

        action = action.toLowerCase();
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();

        switch (action) {
            case "list":
                return listBookmarks(bookmarkManager, arguments);

            case "add":
                return addBookmark(currentProgram, bookmarkManager, arguments);

            case "delete":
                return deleteBookmark(currentProgram, bookmarkManager, arguments);

            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid action: " + action + ". Use 'list', 'add', or 'delete'")
                    .build();
        }
    }

    private McpSchema.CallToolResult listBookmarks(BookmarkManager bookmarkManager, Map<String, Object> arguments) {
        String filterCategory = (String) arguments.get("category");

        StringBuilder result = new StringBuilder();
        result.append("Bookmarks:\n\n");

        // Get all bookmark types
        BookmarkType[] types = bookmarkManager.getBookmarkTypes();
        int totalCount = 0;

        for (BookmarkType type : types) {
            Iterator<Bookmark> bookmarks = bookmarkManager.getBookmarksIterator(type.getTypeString());

            while (bookmarks.hasNext()) {
                Bookmark bookmark = bookmarks.next();

                // Apply category filter if specified
                if (filterCategory != null && !filterCategory.isEmpty()) {
                    if (!bookmark.getCategory().toLowerCase().contains(filterCategory.toLowerCase())) {
                        continue;
                    }
                }

                result.append("- ").append(bookmark.getAddress())
                      .append(" [").append(type.getTypeString()).append("]")
                      .append(" (").append(bookmark.getCategory()).append(")")
                      .append(": ").append(bookmark.getComment())
                      .append("\n");
                totalCount++;
            }
        }

        if (totalCount == 0) {
            result.append("No bookmarks found");
            if (filterCategory != null) {
                result.append(" matching category '").append(filterCategory).append("'");
            }
            result.append(".\n");
        } else {
            result.append("\nTotal: ").append(totalCount).append(" bookmarks\n");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private McpSchema.CallToolResult addBookmark(Program program, BookmarkManager bookmarkManager,
                                                  Map<String, Object> arguments) {
        String addressStr = (String) arguments.get("address");
        String category = (String) arguments.get("category");
        String comment = (String) arguments.get("comment");
        String type = (String) arguments.get("type");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Address is required to add a bookmark")
                .build();
        }

        if (category == null || category.isEmpty()) {
            category = "Analysis";
        }

        if (comment == null || comment.isEmpty()) {
            comment = "MCP Bookmark";
        }

        if (type == null || type.isEmpty()) {
            type = BookmarkType.NOTE;
        }

        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error parsing address: " + e.getMessage())
                .build();
        }

        int txId = program.startTransaction("Add Bookmark");
        try {
            bookmarkManager.setBookmark(address, type, category, comment);
            program.endTransaction(txId, true);

            return McpSchema.CallToolResult.builder()
                .addTextContent("Added bookmark at " + addressStr + " [" + type + "] (" + category + "): " + comment)
                .build();

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error adding bookmark: " + e.getMessage())
                .build();
        }
    }

    private McpSchema.CallToolResult deleteBookmark(Program program, BookmarkManager bookmarkManager,
                                                     Map<String, Object> arguments) {
        String addressStr = (String) arguments.get("address");
        String type = (String) arguments.get("type");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Address is required to delete a bookmark")
                .build();
        }

        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error parsing address: " + e.getMessage())
                .build();
        }

        int txId = program.startTransaction("Delete Bookmark");
        try {
            Bookmark[] bookmarks;
            if (type != null && !type.isEmpty()) {
                Bookmark bookmark = bookmarkManager.getBookmark(address, type, null);
                bookmarks = bookmark != null ? new Bookmark[]{bookmark} : new Bookmark[0];
            } else {
                bookmarks = bookmarkManager.getBookmarks(address);
            }

            if (bookmarks.length == 0) {
                program.endTransaction(txId, false);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No bookmarks found at " + addressStr)
                    .build();
            }

            for (Bookmark bookmark : bookmarks) {
                bookmarkManager.removeBookmark(bookmark);
            }

            program.endTransaction(txId, true);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Deleted " + bookmarks.length + " bookmark(s) at " + addressStr)
                .build();

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error deleting bookmark: " + e.getMessage())
                .build();
        }
    }
}
