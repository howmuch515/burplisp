package burplisp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class BurpLispExtension implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private LispHttpHandler httpHandler;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        // Set extension name
        api.extension().setName("BurpLisp");

        // Initialize and register HTTP handler
        this.httpHandler = new LispHttpHandler(logging, api.scope());
        api.http().registerHttpHandler(httpHandler);

        // Initialize and register GUI Tab
        BurpLispTab tab = new BurpLispTab(api, httpHandler);
        api.userInterface().registerSuiteTab("BurpLisp", tab.getComponent());

        // Gracefully shut down background resources (such as socket REPL) on extension unload
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                tab.cleanup();
            }
        });

        logging.logToOutput("BurpLisp extension initialized successfully.");
    }
}
