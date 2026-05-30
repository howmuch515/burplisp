package burplisp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import clojure.java.api.Clojure;
import clojure.lang.IFn;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashMap;

public class BurpLispTab {
    private final MontoyaApi api;
    private final Logging logging;
    private final LispHttpHandler httpHandler;
    
    private JPanel mainPanel;
    private JTextArea codeTextArea;
    private JCheckBox enabledCheckBox;
    private JCheckBox scopeCheckBox;
    
    // Tool Checkboxes
    private JCheckBox proxyCheckBox;
    private JCheckBox repeaterCheckBox;
    private JCheckBox intruderCheckBox;
    private JCheckBox scannerCheckBox;

    // REPL Server UI
    private JCheckBox replEnabledCheckBox;
    private JTextField replPortField;
    private JLabel replStatusLabel;

    private JComboBox<String> presetComboBox;
    private JButton applyButton;
    private JTextArea logTextArea;

    private final Map<String, String> presetSnippets = new LinkedHashMap<>();

    public BurpLispTab(MontoyaApi api, LispHttpHandler httpHandler) {
        this.api = api;
        this.logging = api.logging();
        this.httpHandler = httpHandler;

        definePresets();
        createUI();
        loadSettings(); // Automatically load persisted configuration on startup
    }

    private void definePresets() {
        presetSnippets.put("Preset: Add Custom Header (Default)", 
            ";;; BurpLisp - Add Custom Header\n" +
            ";;; The Clojure function takes two arguments: request (map) and state (atom).\n" +
            ";;; It must return the modified request map.\n" +
            "\n" +
            "(fn [request state]\n" +
            "  (assoc-in request [:headers \"X-Burp-Lisp\"] \"Active\"))\n");

        presetSnippets.put("Preset: Host-based Conditional Modification", 
            ";;; BurpLisp - Host-based Conditional Modification\n" +
            ";;; Modifies request details ONLY when destination host matches specific target.\n" +
            "\n" +
            "(fn [request state]\n" +
            "  (let [host (get-in request [:service :host])]\n" +
            "    (if (= host \"api.example.com\")\n" +
            "      (-> request\n" +
            "          (assoc-in [:headers \"Authorization\"] \"Bearer SECRET-LISP-TOKEN\")\n" +
            "          (assoc-in [:headers \"X-Lisp-Applied\"] \"true\"))\n" +
            "      request)))\n");

        presetSnippets.put("Preset: Counter using Global State (Atom)", 
            ";;; BurpLisp - Counter using Global State\n" +
            ";;; Increments a thread-safe counter inside the 'state' atom and injects it.\n" +
            "\n" +
            "(fn [request state]\n" +
            "  ;; Update the atom state with a counter, defaulting to 0 if not present\n" +
            "  (swap! state update :counter (fnil inc 0))\n" +
            "  (let [current-count (:counter @state)]\n" +
            "    (assoc-in request [:headers \"X-Request-Index\"] (str current-count))))\n");

        presetSnippets.put("Preset: URL Query Parameter Injection", 
            ";;; BurpLisp - URL Query Parameter Injection\n" +
            ";;; Appends custom audit parameters to the HTTP Query String dynamically.\n" +
            "\n" +
            "(fn [request state]\n" +
            "  (let [current-query (:query request)\n" +
            "        new-query (if (empty? current-query)\n" +
            "                    \"debug=true&test=1\"\n" +
            "                    (str current-query \"&debug=true&test=1\"))]\n" +
            "    (assoc request :query new-query)))\n");

        presetSnippets.put("Preset: Search & Replace JSON Request Body", 
            ";;; BurpLisp - Search & Replace Request Body\n" +
            ";;; Evaluates the body payload and updates structural values.\n" +
            "\n" +
            "(fn [request state]\n" +
            "  (let [body (:body request)]\n" +
            "    (if (and (string? body) (.contains body \"\\\"role\\\"\"))\n" +
            "      (assoc request :body (.replace body \"\\\"role\\\":\\\"user\\\"\" \"\\\"role\\\":\\\"admin\\\"\"))\n" +
            "      request)))\n");
    }

    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 1. Top Settings & Filtering Panel
        JPanel northPanel = new JPanel();
        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));

        // Core settings
        JPanel coreSettingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        enabledCheckBox = new JCheckBox("Enable BurpLisp", false);
        enabledCheckBox.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        enabledCheckBox.addActionListener(e -> {
            httpHandler.setEnabled(enabledCheckBox.isSelected());
            saveSettings();
            log("Extension " + (enabledCheckBox.isSelected() ? "ENABLED" : "DISABLED"));
        });

        scopeCheckBox = new JCheckBox("Target Scope Only", false);
        scopeCheckBox.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        scopeCheckBox.addActionListener(e -> {
            updateHandlerFilters();
            saveSettings();
            log("Target Scope filter " + (scopeCheckBox.isSelected() ? "ENABLED" : "DISABLED"));
        });

        coreSettingsPanel.add(enabledCheckBox);
        coreSettingsPanel.add(scopeCheckBox);
        northPanel.add(coreSettingsPanel);

        // Tool filter checkboxes
        JPanel toolFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        toolFilterPanel.setBorder(new TitledBorder("Applicable Burp Tools"));
        
        proxyCheckBox = new JCheckBox("Proxy", true);
        repeaterCheckBox = new JCheckBox("Repeater", true);
        intruderCheckBox = new JCheckBox("Intruder", true);
        scannerCheckBox = new JCheckBox("Scanner", false);

        ActionListener toolCheckboxListener = e -> {
            updateHandlerFilters();
            saveSettings();
        };

        proxyCheckBox.addActionListener(toolCheckboxListener);
        repeaterCheckBox.addActionListener(toolCheckboxListener);
        intruderCheckBox.addActionListener(toolCheckboxListener);
        scannerCheckBox.addActionListener(toolCheckboxListener);

        toolFilterPanel.add(proxyCheckBox);
        toolFilterPanel.add(repeaterCheckBox);
        toolFilterPanel.add(intruderCheckBox);
        toolFilterPanel.add(scannerCheckBox);
        northPanel.add(toolFilterPanel);

        // Socket REPL Panel
        JPanel replPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        replPanel.setBorder(new TitledBorder("Socket REPL Server (Interactively hack Burp inside Emacs/VS Code)"));
        
        replEnabledCheckBox = new JCheckBox("Enable REPL Server", false);
        replPortField = new JTextField("7888", 6);
        replStatusLabel = new JLabel("Status: Stopped");
        replStatusLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        replStatusLabel.setForeground(Color.GRAY);

        replEnabledCheckBox.addActionListener(e -> {
            toggleReplServer();
            saveSettings();
        });

        replPanel.add(replEnabledCheckBox);
        replPanel.add(new JLabel("Port: "));
        replPanel.add(replPortField);
        replPanel.add(replStatusLabel);
        northPanel.add(replPanel);

        // Preset & Code Actions bar
        JPanel actionPanel = new JPanel(new BorderLayout(5, 5));
        actionPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        JPanel presetContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        presetContainer.add(new JLabel("Preset Snippets: "));
        
        presetComboBox = new JComboBox<>(presetSnippets.keySet().toArray(new String[0]));
        presetComboBox.addActionListener(e -> {
            String selected = (String) presetComboBox.getSelectedItem();
            if (selected != null) {
                int choice = JOptionPane.showConfirmDialog(
                        mainPanel, 
                        "Replace current editor content with this preset?", 
                        "Load Preset", 
                        JOptionPane.YES_NO_OPTION, 
                        JOptionPane.QUESTION_MESSAGE
                );
                if (choice == JOptionPane.YES_OPTION) {
                    codeTextArea.setText(presetSnippets.get(selected));
                    log("Loaded preset: " + selected);
                }
            }
        });
        presetContainer.add(presetComboBox);
        actionPanel.add(presetContainer, BorderLayout.WEST);

        applyButton = new JButton("Compile & Apply");
        applyButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        applyButton.addActionListener(e -> compileAndApply());
        actionPanel.add(applyButton, BorderLayout.EAST);
        northPanel.add(actionPanel);

        mainPanel.add(northPanel, BorderLayout.NORTH);

        // 2. Central Split Pane (Editor and Console)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);

        // Code Editor Panel
        JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
        JLabel editorLabel = new JLabel("Clojure Lisp Expression (Function: [request state] -> modified-request)");
        editorLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        editorPanel.add(editorLabel, BorderLayout.NORTH);

        codeTextArea = new JTextArea();
        codeTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        
        // Default initial code
        codeTextArea.setText(presetSnippets.get("Preset: Add Custom Header (Default)"));
        JScrollPane editorScrollPane = new JScrollPane(codeTextArea);
        editorPanel.add(editorScrollPane, BorderLayout.CENTER);

        splitPane.setTopComponent(editorPanel);

        // Console Log Panel
        JPanel logPanel = new JPanel(new BorderLayout(5, 5));
        JLabel logLabel = new JLabel("Execution Logs / Compiler Errors");
        logLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        logPanel.add(logLabel, BorderLayout.NORTH);

        logTextArea = new JTextArea();
        logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logTextArea.setEditable(false);
        logTextArea.setBackground(new Color(245, 245, 245));
        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        logPanel.add(logScrollPane, BorderLayout.CENTER);

        splitPane.setBottomComponent(logPanel);

        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    private void updateHandlerFilters() {
        httpHandler.setFilters(
                scopeCheckBox.isSelected(),
                proxyCheckBox.isSelected(),
                repeaterCheckBox.isSelected(),
                intruderCheckBox.isSelected(),
                scannerCheckBox.isSelected()
        );
    }

    private void toggleReplServer() {
        if (replEnabledCheckBox.isSelected()) {
            String portText = replPortField.getText().trim();
            int port = 7888;
            try {
                port = Integer.parseInt(portText);
                if (port < 1024 || port > 65535) {
                    throw new NumberFormatException("Port must be between 1024 and 65535.");
                }
            } catch (NumberFormatException e) {
                log("REPL Error: Invalid port. Must be between 1024 and 65535.");
                replEnabledCheckBox.setSelected(false);
                replStatusLabel.setText("Status: Stopped (Invalid port)");
                replStatusLabel.setForeground(Color.RED);
                return;
            }

            final int finalPort = port;
            log("Starting Clojure Socket REPL server on port " + finalPort + "...");
            
            // Asynchronous startup to guarantee no Swing block during socket binding
            new Thread(() -> {
                ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                try {
                    ClassLoader extensionClassLoader = BurpLispTab.class.getClassLoader();
                    Thread.currentThread().setContextClassLoader(extensionClassLoader);

                    IFn startServer = Clojure.var("clojure.core.server", "start-server");
                    
                    Map<Object, Object> args = new HashMap<>();
                    args.put(clojure.lang.Keyword.intern("name"), "burplisp-repl");
                    args.put(clojure.lang.Keyword.intern("port"), finalPort);
                    args.put(clojure.lang.Keyword.intern("accept"), clojure.lang.Symbol.intern("clojure.core.server/repl"));
                    
                    startServer.invoke(clojure.lang.PersistentHashMap.create(args));
                    
                    SwingUtilities.invokeLater(() -> {
                        replStatusLabel.setText("Status: Running on port " + finalPort);
                        replStatusLabel.setForeground(new Color(0, 128, 0));
                        log("Clojure Socket REPL server is now running on port " + finalPort + "!");
                    });
                } catch (Throwable t) {
                    SwingUtilities.invokeLater(() -> {
                        replEnabledCheckBox.setSelected(false);
                        replStatusLabel.setText("Status: Error on startup");
                        replStatusLabel.setForeground(Color.RED);
                        log("REPL Error: Failed to start REPL. " + t.getMessage());
                    });
                } finally {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }).start();
        } else {
            log("Stopping Clojure Socket REPL server...");
            new Thread(() -> {
                ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                try {
                    ClassLoader extensionClassLoader = BurpLispTab.class.getClassLoader();
                    Thread.currentThread().setContextClassLoader(extensionClassLoader);

                    IFn stopServer = Clojure.var("clojure.core.server", "stop-server");
                    
                    Map<Object, Object> args = new HashMap<>();
                    args.put(clojure.lang.Keyword.intern("name"), "burplisp-repl");
                    
                    stopServer.invoke(clojure.lang.PersistentHashMap.create(args));
                    
                    SwingUtilities.invokeLater(() -> {
                        replStatusLabel.setText("Status: Stopped");
                        replStatusLabel.setForeground(Color.GRAY);
                        log("Clojure Socket REPL server stopped.");
                    });
                } catch (Throwable t) {
                    SwingUtilities.invokeLater(() -> {
                        log("REPL Error during stop: " + t.getMessage());
                    });
                } finally {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }).start();
        }
    }

    public void cleanup() {
        if (replEnabledCheckBox.isSelected()) {
            logging.logToOutput("Unloading extension: Safely stopping Clojure Socket REPL server...");
            try {
                ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                try {
                    ClassLoader extensionClassLoader = BurpLispTab.class.getClassLoader();
                    Thread.currentThread().setContextClassLoader(extensionClassLoader);

                    IFn stopServer = Clojure.var("clojure.core.server", "stop-server");
                    
                    Map<Object, Object> args = new HashMap<>();
                    args.put(clojure.lang.Keyword.intern("name"), "burplisp-repl");
                    
                    stopServer.invoke(clojure.lang.PersistentHashMap.create(args));
                    logging.logToOutput("Clojure Socket REPL server stopped successfully on extension unload.");
                } finally {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            } catch (Throwable t) {
                logging.logToError("Error stopping REPL server during extension unload: " + t.getMessage());
            }
        }
    }

    private void compileAndApply() {
        final String code = codeTextArea.getText().trim();
        if (code.isEmpty()) {
            log("Error: Code is empty.");
            return;
        }

        log("Compiling Clojure expression in background thread...");
        applyButton.setEnabled(false);
        applyButton.setText("Compiling...");

        // Non-blocking EDT worker to compile Clojure expressions safely
        new SwingWorker<Boolean, Void>() {
            private String errorMessage = null;
            private IFn compiledFunction = null;

            @Override
            protected Boolean doInBackground() throws Exception {
                ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                try {
                    // Safe classloader wrapping for the background thread
                    ClassLoader extensionClassLoader = BurpLispTab.class.getClassLoader();
                    Thread.currentThread().setContextClassLoader(extensionClassLoader);

                    // Grab clojure load-string compiler
                    IFn loadString = Clojure.var("clojure.core", "load-string");
                    Object result = loadString.invoke(code);

                    if (result instanceof IFn) {
                        compiledFunction = (IFn) result;
                        return true;
                    } else {
                        errorMessage = "The expression did not evaluate to a function (IFn). Got: " + 
                                       (result != null ? result.getClass().getName() : "null");
                        return false;
                    }
                } catch (Throwable t) {
                    java.io.StringWriter sw = new java.io.StringWriter();
                    java.io.PrintWriter pw = new java.io.PrintWriter(sw);
                    t.printStackTrace(pw);
                    errorMessage = t.getMessage() + "\n" + sw.toString();
                    return false;
                } finally {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }

            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        httpHandler.setClojureFunction(compiledFunction);
                        httpHandler.resetStateAtom(); // State atom is cleared on successful compilation
                        log("Success! Compiled and applied Clojure function.");
                        
                        saveSettings(); // Persist configuration on successful compilation

                        // Conveniency Auto-enable
                        if (!enabledCheckBox.isSelected()) {
                            enabledCheckBox.setSelected(true);
                            httpHandler.setEnabled(true);
                            log("Extension auto-enabled.");
                        }
                    } else {
                        log("Compilation Error: " + errorMessage);
                    }
                } catch (Exception e) {
                    log("Unexpected compilation thread worker exception: " + e.getMessage());
                } finally {
                    applyButton.setEnabled(true);
                    applyButton.setText("Compile & Apply");
                }
            }
        }.execute();
    }

    private void loadSettings() {
        try {
            burp.api.montoya.persistence.Preferences prefs = api.persistence().preferences();
            
            // 1. Code
            String savedCode = prefs.getString("burplisp.code");
            if (savedCode != null && !savedCode.trim().isEmpty()) {
                codeTextArea.setText(savedCode);
            }
            
            // 2. Main Enable Checkbox
            Boolean enabled = prefs.getBoolean("burplisp.enabled");
            if (enabled != null) {
                enabledCheckBox.setSelected(enabled);
                httpHandler.setEnabled(enabled);
            }
            
            // 3. Scope filter
            Boolean scopeOnly = prefs.getBoolean("burplisp.scopeOnly");
            if (scopeOnly != null) {
                scopeCheckBox.setSelected(scopeOnly);
            }
            
            // 4. Applicable Tool filters
            Boolean proxy = prefs.getBoolean("burplisp.tool.proxy");
            if (proxy != null) proxyCheckBox.setSelected(proxy);
            
            Boolean repeater = prefs.getBoolean("burplisp.tool.repeater");
            if (repeater != null) repeaterCheckBox.setSelected(repeater);
            
            Boolean intruder = prefs.getBoolean("burplisp.tool.intruder");
            if (intruder != null) intruderCheckBox.setSelected(intruder);
            
            Boolean scanner = prefs.getBoolean("burplisp.tool.scanner");
            if (scanner != null) scannerCheckBox.setSelected(scanner);

            // 5. REPL settings
            String replPort = prefs.getString("burplisp.repl.port");
            if (replPort != null && !replPort.trim().isEmpty()) {
                replPortField.setText(replPort);
            }
            Boolean replEnabled = prefs.getBoolean("burplisp.repl.enabled");
            if (replEnabled != null) {
                replEnabledCheckBox.setSelected(replEnabled);
                if (replEnabled) {
                    toggleReplServer(); // Automatically fire up REPL if preserved as active
                }
            }
            
            updateHandlerFilters();
            log("Configuration loaded successfully from preferences.");
        } catch (Exception e) {
            logging.logToError("Failed to restore persisted BurpLisp settings: " + e.getMessage());
        }
    }

    private void saveSettings() {
        try {
            burp.api.montoya.persistence.Preferences prefs = api.persistence().preferences();
            prefs.setString("burplisp.code", codeTextArea.getText());
            prefs.setBoolean("burplisp.enabled", enabledCheckBox.isSelected());
            prefs.setBoolean("burplisp.scopeOnly", scopeCheckBox.isSelected());
            prefs.setBoolean("burplisp.tool.proxy", proxyCheckBox.isSelected());
            prefs.setBoolean("burplisp.tool.repeater", repeaterCheckBox.isSelected());
            prefs.setBoolean("burplisp.tool.intruder", intruderCheckBox.isSelected());
            prefs.setBoolean("burplisp.tool.scanner", scannerCheckBox.isSelected());

            // Save REPL settings
            prefs.setBoolean("burplisp.repl.enabled", replEnabledCheckBox.isSelected());
            prefs.setString("burplisp.repl.port", replPortField.getText());
        } catch (Exception e) {
            logging.logToError("Failed to persist BurpLisp settings: " + e.getMessage());
        }
    }

    private void log(String message) {
        logTextArea.append("[" + new java.util.Date() + "] " + message + "\n");
        logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        logging.logToOutput(message);
    }

    public Component getComponent() {
        return mainPanel;
    }
}
