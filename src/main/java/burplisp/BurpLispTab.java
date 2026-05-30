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

        presetSnippets.put("Preset: Session maintenance (Request & Response)", 
            ";;; BurpLisp - Bidirectional Session Maintenance Macro\n" +
            ";;; 1. Response hook extracts bearer token from response bodies.\n" +
            ";;; 2. Request hook injects the extracted token into future requests.\n" +
            "\n" +
            "{:request (fn [request state]\n" +
            "            ;; Read authorization token from dynamic state atom\n" +
            "            (if-let [token (:token @state)]\n" +
            "              (assoc-in request [:headers \"Authorization\"] (str \"Bearer \" token))\n" +
            "              request))\n" +
            "\n" +
            " :response (fn [response state]\n" +
            "             ;; Intercept body string to look for JWT access token\n" +
            "             (let [body (:body response)]\n" +
            "               (if (and (string? body) (.contains body \"\\\"access_token\\\"\"))\n" +
            "                 (if-let [token (second (re-find #\"\\\"access_token\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\" body))]\n" +
            "                   (do\n" +
            "                     ;; Store the token inside global state\n" +
            "                     (swap! state assoc :token token)\n" +
            "                     (println \"Extracted Token: \" token)))))\n" +
            "             response)}\n");

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
            private Object compilationResult = null;

            @Override
            protected Boolean doInBackground() throws Exception {
                ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
                try {
                    // Safe classloader wrapping for the background thread
                    ClassLoader extensionClassLoader = BurpLispTab.class.getClassLoader();
                    Thread.currentThread().setContextClassLoader(extensionClassLoader);

                    // Grab clojure load-string compiler
                    IFn loadString = Clojure.var("clojure.core", "load-string");
                    compilationResult = loadString.invoke(code);

                    if (compilationResult instanceof IFn || compilationResult instanceof Map) {
                        return true;
                    } else {
                        errorMessage = "The expression did not evaluate to a function (IFn) or a hook map (Map). Got: " + 
                                       (compilationResult != null ? compilationResult.getClass().getName() : "null");
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
                        httpHandler.setClojureFunctions(compilationResult);
                        httpHandler.resetStateAtom(); // State atom is cleared on successful compilation
                        log("Success! Compiled and applied Clojure script.");
                        
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
