package burplisp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import clojure.java.api.Clojure;
import clojure.lang.IFn;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpLispTab {
    private final MontoyaApi api;
    private final Logging logging;
    private final LispHttpHandler httpHandler;
    
    private JPanel mainPanel;
    private JTextArea codeTextArea;
    private JCheckBox enabledCheckBox;
    private JButton applyButton;
    private JTextArea logTextArea;

    public BurpLispTab(MontoyaApi api, LispHttpHandler httpHandler) {
        this.api = api;
        this.logging = api.logging();
        this.httpHandler = httpHandler;

        createUI();
    }

    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top Settings Panel
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enabledCheckBox = new JCheckBox("Enable BurpLisp", false);
        enabledCheckBox.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        enabledCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                httpHandler.setEnabled(enabledCheckBox.isSelected());
                log("Extension " + (enabledCheckBox.isSelected() ? "ENABLED" : "DISABLED"));
            }
        });
        topPanel.add(enabledCheckBox);
        mainPanel.add(topPanel, BorderLayout.NORTH);

        // Center Split Pane (Editor and Console)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);

        // Code Editor Panel
        JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
        JLabel editorLabel = new JLabel("Clojure Lisp Expression (Function that maps: headers -> modified-headers)");
        editorLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        editorPanel.add(editorLabel, BorderLayout.NORTH);

        codeTextArea = new JTextArea();
        codeTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        
        // Default Sample Code
        String defaultCode = 
            ";;; BurpLisp - Modify request headers using Clojure!\n" +
            ";;; The expression should evaluate to a function taking a map of headers\n" +
            ";;; and returning the modified map of headers.\n" +
            "\n" +
            "(fn [headers]\n" +
            "  ;; assoc adds or overwrites headers\n" +
            "  ;; dissoc removes headers, e.g. (dissoc headers \"User-Agent\")\n" +
            "  (-> headers\n" +
            "      (assoc \"X-Burp-Lisp\" \"Active\")\n" +
            "      (assoc \"User-Agent\" \"BurpLispAgent/1.0\")))\n";
        
        codeTextArea.setText(defaultCode);
        JScrollPane editorScrollPane = new JScrollPane(codeTextArea);
        editorPanel.add(editorScrollPane, BorderLayout.CENTER);

        // Apply Button
        applyButton = new JButton("Compile & Apply");
        applyButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        applyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                compileAndApply();
            }
        });
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(applyButton);
        editorPanel.add(buttonPanel, BorderLayout.SOUTH);

        splitPane.setTopComponent(editorPanel);

        // Log Console Panel
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

    private void compileAndApply() {
        String code = codeTextArea.getText().trim();
        if (code.isEmpty()) {
            log("Error: Code is empty.");
            return;
        }

        log("Compiling Clojure expression...");
        
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            // Swap to the extension's classloader to resolve Burp Suite classpath encapsulation issues.
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);

            // Load Clojure load-string function
            IFn loadString = Clojure.var("clojure.core", "load-string");
            
            // Evaluate the code
            Object result = loadString.invoke(code);

            if (result instanceof IFn) {
                httpHandler.setClojureFunction((IFn) result);
                log("Success! Compiled and applied Clojure function.");
                
                // Auto-enable when compilation succeeds for user convenience
                if (!enabledCheckBox.isSelected()) {
                    enabledCheckBox.setSelected(true);
                    httpHandler.setEnabled(true);
                    log("Extension auto-enabled.");
                }
            } else {
                log("Error: The expression did not evaluate to a function (IFn). Got: " + (result != null ? result.getClass().getName() : "null"));
            }
        } catch (Throwable t) {
            log("Compilation Error: " + t.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            java.io.PrintWriter pw = new java.io.PrintWriter(sw);
            t.printStackTrace(pw);
            log(sw.toString());
        } finally {
            // Restore original classloader
            Thread.currentThread().setContextClassLoader(originalClassLoader);
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
