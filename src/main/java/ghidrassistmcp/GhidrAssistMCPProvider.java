/* 
 * 
 */
package ghidrassistmcp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * UI Provider for the GhidrAssistMCP plugin featuring configuration and logging tabs.
 */
public class GhidrAssistMCPProvider extends ComponentProvider implements McpEventListener {
    
    private static final String NAME = "GhidrAssistMCP";
    private static final String OWNER = "GhidrAssistMCPPlugin";
    
    // Settings constants
    private static final String SETTINGS_CATEGORY = "GhidrAssistMCP";
    private static final String HOST_SETTING = "Server Host";
    private static final String PORT_SETTING = "Server Port";
    private static final String ENABLED_SETTING = "Server Enabled";
    private static final String TOOL_PREFIX = "Tool.";
    
    // Default values
    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 8080;
    private static final boolean DEFAULT_ENABLED = true;
    
    private final PluginTool tool;
    private final GhidrAssistMCPPlugin plugin;
    private JTabbedPane tabbedPane;
    
    // Configuration tab components
    private JTextField hostField;
    private JSpinner portSpinner;
    private JCheckBox enabledCheckBox;
    private JTable toolsTable;
    private DefaultTableModel toolsTableModel;
    private JButton saveButton;
    private Map<String, Boolean> toolEnabledStates;
    
    // Log tab components
    private JTextArea logTextArea;
    private JButton clearButton;
    private SimpleDateFormat dateFormat;
    
    public GhidrAssistMCPProvider(PluginTool tool, GhidrAssistMCPPlugin plugin) {
        super(tool, NAME, OWNER);
        this.tool = tool;
        this.plugin = plugin;
        this.toolEnabledStates = new HashMap<>();
        this.dateFormat = new SimpleDateFormat("HH:mm:ss");
        
        buildComponent();
        createActions();
        // Don't load settings yet - wait for backend to be ready
        
        setHelpLocation(new HelpLocation("GhidrAssistMCP", "GhidrAssistMCP_Provider"));
        setVisible(true);
        
        // Add focus listener to refresh tools when window receives focus
        addFocusListener();
    }
    
    private void buildComponent() {
        tabbedPane = new JTabbedPane();
        
        // Configuration tab
        JPanel configPanel = createConfigurationPanel();
        tabbedPane.addTab("Configuration", configPanel);
        
        // Log tab
        JPanel logPanel = createLogPanel();
        tabbedPane.addTab("Log", logPanel);
        
        // Component will be returned by getComponent() method
    }
    
    private JPanel createConfigurationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Server settings panel
        JPanel serverPanel = new JPanel(new GridBagLayout());
        serverPanel.setBorder(BorderFactory.createTitledBorder("Server Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Host setting
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        serverPanel.add(new JLabel("Host:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        hostField = new JTextField(DEFAULT_HOST, 20);
        serverPanel.add(hostField, gbc);
        
        // Port setting
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        serverPanel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        portSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_PORT, 1, 65535, 1));
        serverPanel.add(portSpinner, gbc);
        
        // Enabled setting
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE;
        enabledCheckBox = new JCheckBox("Enable MCP Server", DEFAULT_ENABLED);
        serverPanel.add(enabledCheckBox, gbc);
        
        panel.add(serverPanel, BorderLayout.NORTH);
        
        // Tools panel
        JPanel toolsPanel = new JPanel(new BorderLayout());
        toolsPanel.setBorder(BorderFactory.createTitledBorder("MCP Tools"));
        
        // Tools table
        String[] columnNames = {"Enabled", "Tool Name", "Description"};
        toolsTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
            
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only the checkbox column is editable
            }
        };
        
        toolsTable = new JTable(toolsTableModel);
        toolsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        toolsTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        toolsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        
        JScrollPane scrollPane = new JScrollPane(toolsTable);
        scrollPane.setPreferredSize(new Dimension(500, 200));
        toolsPanel.add(scrollPane, BorderLayout.CENTER);
        
        panel.add(toolsPanel, BorderLayout.CENTER);
        
        // Save button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(new SaveConfigurationListener());
        buttonPanel.add(saveButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Log text area
        logTextArea = new JTextArea(20, 60);
        logTextArea.setEditable(false);
        logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logTextArea.setBackground(Color.BLACK);
        logTextArea.setForeground(Color.GREEN);
        JScrollPane scrollPane = new JScrollPane(logTextArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Clear button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> clearLog());
        buttonPanel.add(clearButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void createActions() {
        DockingAction refreshAction = new DockingAction("Refresh", OWNER) {
            @Override
            public void actionPerformed(ActionContext context) {
                refreshToolsList();
            }
        };
        refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        refreshAction.setDescription("Refresh tools list");
        refreshAction.setHelpLocation(new HelpLocation("GhidrAssistMCP", "Refresh"));
        
        addLocalAction(refreshAction);
    }
    
    private void addFocusListener() {
        // Add focus listener to the main component to refresh tools when window receives focus
        tabbedPane.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                // Refresh tools list when the window receives focus
                refreshToolsList();
            }
            
            @Override
            public void focusLost(FocusEvent e) {
                // No action needed when focus is lost
            }
        });
    }
    
    public void refreshToolsList() {
        // Clear existing rows
        toolsTableModel.setRowCount(0);
        
        // Get tools from backend
        if (plugin != null && plugin.getBackend() != null) {
            try {
                // Get all tools (including disabled ones) for configuration display
                var tools = plugin.getBackend().getAllTools();
                
                // Sync enabled states with backend
                var backendStates = plugin.getBackend().getToolEnabledStates();
                toolEnabledStates.putAll(backendStates);
                
                for (var tool1 : tools) {
                    String toolName = tool1.name();
                    boolean enabled = toolEnabledStates.getOrDefault(toolName, true);
                    String description = tool1.description();
                    
                    // Truncate long descriptions
                    if (description != null && description.length() > 80) {
                        description = description.substring(0, 77) + "...";
                    }
                    
                    toolsTableModel.addRow(new Object[]{enabled, toolName, description});
                }
                logMessage("Refreshed tools list: " + tools.size() + " tools available");
            } catch (Exception e) {
                logMessage("Error refreshing tools list: " + e.getMessage());
            }
        } else {
            logMessage("Backend not available yet - tools list empty");
        }
    }
    
    private void loadSettings() {
        Options options = tool.getOptions(SETTINGS_CATEGORY);
        
        // Load server settings
        String host = options.getString(HOST_SETTING, DEFAULT_HOST);
        int port = options.getInt(PORT_SETTING, DEFAULT_PORT);
        boolean enabled = options.getBoolean(ENABLED_SETTING, DEFAULT_ENABLED);
        
        hostField.setText(host);
        portSpinner.setValue(port);
        enabledCheckBox.setSelected(enabled);
        
        // Load tool enabled states
        toolEnabledStates.clear();
        if (plugin != null && plugin.getBackend() != null) {
            try {
                var tools = plugin.getBackend().getAllTools();
                int loadedCount = 0;
                for (var tool1 : tools) {
                    String toolName = tool1.name();
                    boolean toolEnabled = options.getBoolean(TOOL_PREFIX + toolName, true);
                    toolEnabledStates.put(toolName, toolEnabled);
                    loadedCount++;
                }
                // Update backend with loaded settings
                plugin.getBackend().updateToolEnabledStates(toolEnabledStates);
                logMessage("Loaded tool states from settings: " + loadedCount + " tools configured");
            } catch (Exception e) {
                logMessage("Error loading tool states: " + e.getMessage());
            }
        } else {
            logMessage("Backend not available - skipping tool state loading");
        }
        
        // Note: Options change listening would require additional implementation
    }
    
    private void saveSettings() {
        Options options = tool.getOptions(SETTINGS_CATEGORY);
        
        // Save server settings
        options.setString(HOST_SETTING, hostField.getText());
        options.setInt(PORT_SETTING, (Integer) portSpinner.getValue());
        options.setBoolean(ENABLED_SETTING, enabledCheckBox.isSelected());
        
        // Save tool enabled states from table
        int savedCount = 0;
        for (int i = 0; i < toolsTableModel.getRowCount(); i++) {
            String toolName = (String) toolsTableModel.getValueAt(i, 1);
            boolean enabled = (Boolean) toolsTableModel.getValueAt(i, 0);
            toolEnabledStates.put(toolName, enabled);
            options.setBoolean(TOOL_PREFIX + toolName, enabled);
            savedCount++;
        }
        
        logMessage("Saved tool states to settings: " + savedCount + " tools configured");
        
        // Apply changes to the plugin
        plugin.applyConfiguration(hostField.getText(), (Integer) portSpinner.getValue(), 
                                enabledCheckBox.isSelected(), toolEnabledStates);
    }
    
    public void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = dateFormat.format(new Date());
            String logEntry = "[" + timestamp + "] " + message + "\n";
            logTextArea.append(logEntry);
            logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        });
    }
    
    public void logRequest(String method, String params) {
        String truncatedParams = params.length() > 60 ? params.substring(0, 77) + "..." : params;
        logMessage("REQ: " + method + " " + truncatedParams.replace("\n", "\\n"));
    }
    
    public void logResponse(String method, String response) {
        String truncatedResponse = response.length() > 60 ? response.substring(0, 77) + "..." : response;
        logMessage("RES: " + method + " " + truncatedResponse.replace("\n", "\\n"));
    }
    
    public void logSession(String event) {
        logMessage("SESSION: " + event);
    }
    
    private void clearLog() {
        logTextArea.setText("");
    }
    
    // Add the required getComponent method
    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }
    
    private class SaveConfigurationListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            saveSettings();
            logMessage("Configuration saved");
        }
    }
    
    // Getters for current configuration
    public String getHost() {
        return hostField.getText();
    }
    
    public int getPort() {
        return (Integer) portSpinner.getValue();
    }
    
    public boolean isServerEnabled() {
        return enabledCheckBox.isSelected();
    }
    
    public Map<String, Boolean> getToolEnabledStates() {
        return new HashMap<>(toolEnabledStates);
    }
    
    /**
     * Public method to refresh tools list - can be called when backend becomes available
     */
    public void onBackendReady() {
        // Load settings now that backend is ready
        loadSettings();
        refreshToolsList();
        logMessage("Backend ready - settings loaded and tools list refreshed");
    }
    
    // McpEventListener implementation
    @Override
    public void onToolRequest(String toolName, String parameters) {
        logRequest(toolName, parameters);
    }
    
    @Override
    public void onToolResponse(String toolName, String response) {
        logResponse(toolName, response);
    }
    
    @Override
    public void onSessionEvent(String event) {
        logSession(event);
    }
    
    @Override
    public void onLogMessage(String message) {
        logMessage(message);
    }
}