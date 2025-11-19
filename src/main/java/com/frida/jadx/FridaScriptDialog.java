package com.frida.jadx;

import com.frida.jadx.templates.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Frida script library dialog
 * Displays different categories of Hook scripts in a tree structure
 */
public class FridaScriptDialog extends JDialog {
    
    private static final Logger logger = LoggerFactory.getLogger(FridaScriptDialog.class);
    
    private JTree scriptTree;
    private JTextArea scriptTextArea;
    private DefaultMutableTreeNode rootNode;
    private PluginConfig config;
    private JButton copyButton;
    private JButton copyWithoutCommentsButton;
    private JButton languageButton;
    private JButton closeButton;
    private JButton expandAllButton;
    private JButton collapseAllButton;

    public FridaScriptDialog(JFrame parent, PluginConfig config) {
        super(parent, "Frida实用脚本库", false);
        this.config = config;
        initUI();
        loadScriptTemplates();
        updateLanguage(); // Apply language settings
        
        setSize(900, 600);
        setLocationRelativeTo(parent);
    }

    /**
     * Initialize UI components
     */
    private void initUI() {
        setLayout(new BorderLayout(10, 10));

        // Create tree structure
        rootNode = new DefaultMutableTreeNode("Frida实用脚本库");
        scriptTree = new JTree(rootNode);
        scriptTree.setRootVisible(true);
        
        // Set tree selection listener - single click to view script
        scriptTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) scriptTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ScriptTemplate) {
                displayScript((ScriptTemplate) node.getUserObject());
            }
        });

        JScrollPane treeScrollPane = new JScrollPane(scriptTree);
        treeScrollPane.setPreferredSize(new Dimension(300, 0));

        // Create script display area
        scriptTextArea = new JTextArea();
        scriptTextArea.setEditable(false);
        
        // Set font for Chinese character support
        Font font = new Font("Microsoft YaHei UI", Font.PLAIN, 13);
        if (font.getFamily().equals("Dialog")) {
            // If Microsoft YaHei UI not available, use default monospaced font
            font = new Font("Monospaced", Font.PLAIN, 12);
        }
        scriptTextArea.setFont(font);
        scriptTextArea.setTabSize(4);
        scriptTextArea.setText("Click tree node to view Frida script template");

        JScrollPane textScrollPane = new JScrollPane(scriptTextArea);

        // Create operation button panel
        JPanel buttonPanel = new JPanel(new BorderLayout());
        
        // Left side buttons (Language, Expand/Collapse)
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        languageButton = new JButton();
        languageButton.addActionListener(e -> toggleLanguage());
        leftPanel.add(languageButton);
        
        expandAllButton = new JButton();
        expandAllButton.addActionListener(e -> expandAllNodes());
        leftPanel.add(expandAllButton);
        
        collapseAllButton = new JButton();
        collapseAllButton.addActionListener(e -> collapseAllNodes());
        leftPanel.add(collapseAllButton);
        
        // Copy and Close buttons (right side)
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        copyButton = new JButton();
        copyButton.addActionListener(e -> copyScriptToClipboard(false));
        copyWithoutCommentsButton = new JButton();
        copyWithoutCommentsButton.addActionListener(e -> copyScriptToClipboard(true));
        closeButton = new JButton();
        closeButton.addActionListener(e -> setVisible(false));
        rightPanel.add(copyButton);
        rightPanel.add(copyWithoutCommentsButton);
        rightPanel.add(closeButton);
        
        buttonPanel.add(leftPanel, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);

        // Create split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScrollPane, textScrollPane);
        splitPane.setDividerLocation(300);

        // Add components
        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    /**
     * Load script templates (7 categories)
     */
    private void loadScriptTemplates() {
        logger.info("Loading Frida script templates...");
        boolean isEnglish = config.isEnglish();
        
        // Category 1: Frida Basics
        String basicsTitle = isEnglish ? "1. Frida Basics" : "1. Frida基本使用";
        DefaultMutableTreeNode basicsNode = new DefaultMutableTreeNode(basicsTitle);
        basicsNode.add(createScriptNode(FridaBasics.HOOK_EXAMPLES, 0));
        rootNode.add(basicsNode);
        logger.debug("Loaded {} Frida Basics scripts", basicsNode.getChildCount());
        
        // Category 2: Helper Functions
        String helperTitle = isEnglish ? "2. Helper Functions" : "2. 辅助函数";
        DefaultMutableTreeNode helperNode = new DefaultMutableTreeNode(helperTitle);
        helperNode.add(createScriptNode(HelperFunctions.PRINT_CALLSTACK, 0));
        helperNode.add(createScriptNode(HelperFunctions.DATA_CONVERT, 1));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_ARGS, 2));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_MAP, 3));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_STRING_ARRAY, 4));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_METHOD_SIGNATURE, 5));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_CUSTOM_OBJECT, 6));
        rootNode.add(helperNode);
        logger.debug("Loaded {} Helper Functions scripts", helperNode.getChildCount());

        // Category 3: Hook JDK
        String jdkTitle = isEnglish ? "3. Hook JDK" : "3. Hook JDK";
        DefaultMutableTreeNode jdkNode = new DefaultMutableTreeNode(jdkTitle);
        jdkNode.add(createScriptNode(HookJDK.MONITOR_ALL_MAP, 0));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_ARRAYLIST, 1));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_BASE64_ANDROID, 2));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_BASE64_JAVA, 3));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_COLLECTIONS, 4));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_FILE, 5));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_STRING, 6));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_STRINGBUILDER, 7));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_STRINGFACTORY, 8));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_URL, 9));
        jdkNode.add(createScriptNode(HookJDK.PRINT_MAP, 10));
        rootNode.add(jdkNode);
        logger.debug("Loaded {} Hook JDK scripts", jdkNode.getChildCount());

        // Category 4: Hook Android
        String androidTitle = isEnglish ? "4. Hook Android" : "4. Hook Android";
        DefaultMutableTreeNode androidNode = new DefaultMutableTreeNode(androidTitle);
        androidNode.add(createScriptNode(HookAndroid.BLOCK_POPUP, 0));
        androidNode.add(createScriptNode(HookAndroid.HOOK_CRASH, 1));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_ACTIVITY, 2));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_DIALOG, 3));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_EDITTEXT, 4));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_LOG, 5));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_SHAREDPREFERENCES, 6));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_TEXTUTILS, 7));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST, 8));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_WEBVIEW, 9));
        rootNode.add(androidNode);
        logger.debug("Loaded {} Hook Android scripts", androidNode.getChildCount());

        // Category 5: Hook Third-Party
        String thirdPartyTitle = isEnglish ? "5. Hook Third-Party" : "5. Hook第三方库";
        DefaultMutableTreeNode thirdPartyNode = new DefaultMutableTreeNode(thirdPartyTitle);
        thirdPartyNode.add(createScriptNode(HookThirdParty.MONITOR_JSONOBJECT, 0));
        thirdPartyNode.add(createScriptNode(HookThirdParty.MONITOR_OKHTTP, 1));
        rootNode.add(thirdPartyNode);
        logger.debug("Loaded {} Hook Third-Party scripts", thirdPartyNode.getChildCount());

        // Category 6: Hook JNI (currently empty, user will add JNI scripts)
        String jniTitle = isEnglish ? "6. Hook JNI" : "6. JNI相关";
        DefaultMutableTreeNode jniNode = new DefaultMutableTreeNode(jniTitle);
        // TODO: Add JNI hook scripts here when available
        // jniNode.add(createScriptNode(HookJNI.YOUR_SCRIPT, 0));
        rootNode.add(jniNode);
        logger.debug("Loaded {} Hook JNI scripts", jniNode.getChildCount());
        
        // Category 7: Frida Advanced
        String fridaTitle = isEnglish ? "7. Frida Advanced" : "7. Frida进阶";
        DefaultMutableTreeNode fridaNode = new DefaultMutableTreeNode(fridaTitle);
        fridaNode.add(createScriptNode(FridaAdvanced.CALL_METHODS, 0));
        fridaNode.add(createScriptNode(FridaAdvanced.CLASSLOADER_HELPER, 1));
        fridaNode.add(createScriptNode(FridaAdvanced.DUMP_CERTIFICATE, 2));
        fridaNode.add(createScriptNode(FridaAdvanced.LOAD_DEX, 3));
        rootNode.add(fridaNode);
        logger.debug("Loaded {} Frida Advanced scripts", fridaNode.getChildCount());

        // Refresh tree
        DefaultTreeModel model = (DefaultTreeModel) scriptTree.getModel();
        model.reload();
        
        // Expand all nodes by default
        expandAllNodes(scriptTree, 0, scriptTree.getRowCount());
        
        logger.info("Script templates loaded successfully. Total categories: 7");
    }

    /**
     * Create script node from ScriptEntry with index
     */
    private DefaultMutableTreeNode createScriptNode(FridaTemplates.ScriptEntry entry, int index) {
        boolean isEnglish = config.isEnglish();
        String displayName = (index + 1) + ". " + entry.getName(isEnglish);
        ScriptTemplate template = new ScriptTemplate(displayName, entry.code);
        return new DefaultMutableTreeNode(template);
    }

    /**
     * display Script Code
     */
    private void displayScript(ScriptTemplate template) {
        scriptTextArea.setText(template.getScript());
        scriptTextArea.setCaretPosition(0); // Scroll to top
    }

    /**
     * Copy script to clipboard
     * @param removeComments true to remove comments, false to keep them
     */
    private void copyScriptToClipboard(boolean removeComments) {
        String script = scriptTextArea.getText();
        if (script != null && !script.isEmpty()) {
            if (removeComments) {
                script = removeComments(script);
            }
            StringSelection selection = new StringSelection(script);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            
            String message = config.isEnglish() ? 
                (removeComments ? "Script copied to clipboard (no comments)!" : "Script copied to clipboard!") :
                (removeComments ? "脚本已复制到剪贴板（无注释）！" : "脚本已复制到剪贴板！");
            String title = config.isEnglish() ? "Success" : "成功";
            JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * Remove comments from JavaScript code
     * @param code JavaScript code
     * @return Code without comments
     */
    private String removeComments(String code) {
        StringBuilder result = new StringBuilder();
        String[] lines = code.split("\n");
        
        for (String line : lines) {
            // Skip lines that start with // (after trimming)
            String trimmed = line.trim();
            if (trimmed.startsWith("//")) {
                continue;
            }
            
            // For lines with inline comments, remove the // part
            int commentIndex = line.indexOf("//");
            if (commentIndex > 0) {
                // Check if // is inside a string
                String beforeComment = line.substring(0, commentIndex);
                int singleQuotes = countOccurrences(beforeComment, '\'');
                int doubleQuotes = countOccurrences(beforeComment, '"');
                int backticks = countOccurrences(beforeComment, '`');
                
                // If quotes/backticks are balanced, // is not in a string
                if (singleQuotes % 2 == 0 && doubleQuotes % 2 == 0 && backticks % 2 == 0) {
                    line = line.substring(0, commentIndex).stripTrailing();
                }
            }
            
            // Only add non-empty lines
            if (!line.trim().isEmpty()) {
                result.append(line).append("\n");
            }
        }
        
        return result.toString();
    }
    
    /**
     * Count occurrences of a character in a string
     */
    private int countOccurrences(String str, char ch) {
        int count = 0;
        for (char c : str.toCharArray()) {
            if (c == ch) count++;
        }
        return count;
    }
    
    /**
     * Toggle language between English and Chinese
     */
    private void toggleLanguage() {
        config.toggleLanguage();
        updateLanguage();
        
        // Reload script templates to refresh category names
        rootNode.removeAllChildren();
        loadScriptTemplates();
        
        String message = config.isEnglish() ? 
            "Language switched to English. Dialog will refresh." : 
            "已切换到中文。对话框将刷新。";
        String title = config.isEnglish() ? "Language Changed" : "语言已更改";
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Update all UI text based on current language setting
     */
    private void updateLanguage() {
        boolean isEnglish = config.isEnglish();
        
        // Update dialog title
        setTitle(isEnglish ? "Frida Script Library" : "Frida实用脚本库");
        
        // Update root node text
        rootNode.setUserObject(isEnglish ? "Frida Script Library" : "Frida实用脚本库");
        
        // Update buttons
        languageButton.setText(isEnglish ? "中文" : "English");
        languageButton.setToolTipText(isEnglish ? "Switch to Chinese" : "切换到英文");
        expandAllButton.setText(isEnglish ? "Expand All" : "展开全部");
        expandAllButton.setToolTipText(isEnglish ? "Expand all tree nodes" : "展开所有树节点");
        collapseAllButton.setText(isEnglish ? "Collapse All" : "折叠全部");
        collapseAllButton.setToolTipText(isEnglish ? "Collapse all tree nodes" : "折叠所有树节点");
        copyButton.setText(isEnglish ? "Copy Script" : "复制脚本");
        copyWithoutCommentsButton.setText(isEnglish ? "Copy (No Comments)" : "复制（无注释）");
        copyWithoutCommentsButton.setToolTipText(isEnglish ? "Copy script without comments" : "复制脚本不包含注释");
        closeButton.setText(isEnglish ? "Close" : "关闭");
        
        // Update placeholder text
        if (scriptTextArea.getText().contains("Click tree node") || 
            scriptTextArea.getText().contains("点击树节点")) {
            scriptTextArea.setText(isEnglish ? 
                "Click tree node to view Frida script library" : 
                "点击树节点查看Frida实用脚本库");
        }
        
        logger.info("UI language updated to: {}", isEnglish ? "English" : "Chinese");
    }

    /**
     * Expand all tree nodes (called by button)
     */
    private void expandAllNodes() {
        expandAllNodes(scriptTree, 0, scriptTree.getRowCount());
        logger.debug("All tree nodes expanded");
    }
    
    /**
     * Collapse all tree nodes (called by button)
     */
    private void collapseAllNodes() {
        int row = scriptTree.getRowCount() - 1;
        while (row >= 1) { // Keep root expanded
            scriptTree.collapseRow(row);
            row--;
        }
        logger.debug("All tree nodes collapsed");
    }
    
    /**
     * 展开所有树节点（递归辅助方法）
     */
    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        for (int i = startingIndex; i < rowCount; ++i) {
            tree.expandRow(i);
        }

        if (tree.getRowCount() != rowCount) {
            expandAllNodes(tree, rowCount, tree.getRowCount());
        }
    }

    /**
     * 脚本数据类
     */
    static class ScriptTemplate {
        private final String name;
        private final String script;

        public ScriptTemplate(String name, String script) {
            this.name = name;
            this.script = script;
        }

        public String getName() {
            return name;
        }

        public String getScript() {
            return script;
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
