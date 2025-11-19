package com.frida.jadx;

import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.gui.ui.MainWindow;
import jadx.gui.settings.JadxSettings;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.gui.utils.LangLocale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 * JADX Frida Hook All Plugin
 * Provides practical Frida Hook scripts for JDK, Android APIs and JNI
 */
public class JadxFridaHookAll implements JadxPlugin {
    
    private static final Logger logger = LoggerFactory.getLogger(JadxFridaHookAll.class);
    public static final String PLUGIN_ID = "jadx-frida-hookall";
    
    private MainWindow mainWindow;
    private FridaScriptDialog scriptDialog;
    private PluginConfig config;
    private JadxGuiContext guiContext;

    @Override
    public void init(JadxPluginContext context) {
        // Check GUI context
        if (context.getGuiContext() == null) {
            logger.info("Frida HookAll Plugin: Running in non-GUI mode, plugin features disabled.");
            return;
        }

        try {
            this.guiContext = context.getGuiContext();
            this.mainWindow = (MainWindow) guiContext.getMainFrame();
            if (this.mainWindow == null) {
                logger.error("Frida HookAll Plugin: Main window is null.");
                return;
            }

            logger.info("Frida HookAll Plugin: Initializing...");
            
            // Initialize configuration with JADX language settings
            config = new PluginConfig();
            autoDetectLanguage();
            logger.info("Plugin configuration loaded. Language: {}", config.getLanguage());
            
            // Add menu items
            addMenuItems();
            
            logger.info("Frida HookAll Plugin: Initialized successfully.");
            
        } catch (Exception e) {
            logger.error("Frida HookAll Plugin: Initialization error: " + e.getMessage(), e);
        }
    }

    @Override
    public JadxPluginInfo getPluginInfo() {
        return JadxPluginInfoBuilder.pluginId(PLUGIN_ID)
                .name("Frida HookAll")
                .description("Frida Script Library | Frida实用脚本库\nPractical Frida Hook scripts for Java/Android reverse engineering.\nCtrl+Alt+H to open.\nAuthor: x1a0f3n9(LunFengChen)\nversion: 1.0.0")
                .homepage("https://github.com/LunFengChen/jadx-frida-hookAll")
                .build();
    }

    /**
     * Auto-detect language from JADX settings
     */
    private void autoDetectLanguage() {
        try {
            JadxSettings settings = mainWindow.getSettings();
            if (settings != null) {
                LangLocale langLocale = settings.getLangLocale();
                String langCode = langLocale.get().getLanguage();
                
                // If JADX is set to Chinese, use Chinese; otherwise use English
                if ("zh".equals(langCode)) {
                    config.setLanguage("zh");
                    logger.info("Auto-detected Chinese language from JADX settings");
                } else {
                    config.setLanguage("en");
                    logger.info("Auto-detected non-Chinese language from JADX settings, using English");
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to auto-detect language, using default: {}", e.getMessage());
        }
    }

    /**
     * Add menu items and keyboard shortcuts
     */
    private void addMenuItems() {
        SwingUtilities.invokeLater(() -> {
            try {
                JMenuBar menuBar = mainWindow.getJMenuBar();
                if (menuBar == null) {
                    logger.warn("Frida HookAll Plugin: Menu bar not found");
                    return;
                }

                // Find or create Plugins menu
                JMenu pluginsMenu = findOrCreatePluginsMenu(menuBar);

                // Create Frida HookAll menu item with bilingual support
                String menuText = config.isEnglish() ? "Frida Script Library" : "Frida实用脚本库";
                JMenuItem fridaMenuItem = new JMenuItem(menuText);
                
                // Add shortcut Ctrl+Alt+H (H for Hook)
                fridaMenuItem.setAccelerator(KeyStroke.getKeyStroke(
                        KeyEvent.VK_H, 
                        ActionEvent.CTRL_MASK | ActionEvent.ALT_MASK));
                
                fridaMenuItem.addActionListener(e -> showFridaScriptDialog());
                
                pluginsMenu.add(fridaMenuItem);

                logger.info("Frida HookAll Plugin: Menu item added with shortcut Ctrl+Alt+H");

            } catch (Exception e) {
                logger.error("Frida HookAll Plugin: Error adding menu items: " + e.getMessage(), e);
            }
        });
    }

    /**
     * Find or create Plugins menu
     */
    private JMenu findOrCreatePluginsMenu(JMenuBar menuBar) {
        // Find existing Plugins menu
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenu menu = menuBar.getMenu(i);
            if (menu != null && ("Plugins".equals(menu.getText()) || "Plugin".equals(menu.getText()))) {
                return menu;
            }
        }

        // Create new Plugins menu
        JMenu pluginsMenu = new JMenu("Plugins");

        // Try to insert before Help menu
        boolean inserted = false;
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenu menu = menuBar.getMenu(i);
            if (menu != null && "Help".equals(menu.getText())) {
                menuBar.add(pluginsMenu, i);
                inserted = true;
                break;
            }
        }

        if (!inserted) {
            menuBar.add(pluginsMenu);
        }

        return pluginsMenu;
    }

    /**
     * Show Frida script dialog
     */
    private void showFridaScriptDialog() {
        if (scriptDialog == null) {
            scriptDialog = new FridaScriptDialog(mainWindow, config);
        }
        scriptDialog.setVisible(true);
    }
}
