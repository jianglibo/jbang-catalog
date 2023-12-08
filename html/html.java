///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "html", mixinStandardHelpOptions = true, version = "html 0.1", description = "html made with jbang")
class html {

    static final String blankHtml = """
            <!doctype html>
            <html lang=en>
            <head>
            <meta charset=utf-8>
            <title>blah</title>
            </head>
            <body>
            <p>I'm the content</p>
            </body>
            </html>
            """;

    @Parameters(index = "0", description = "The greeting to print", defaultValue = "World!")
    private String greeting;

    public static void main(String... args) {
        int exitCode = new CommandLine(new html()).execute(args);
        System.exit(exitCode);
    }

    @Command(mixinStandardHelpOptions = true)
    void blankHtml(@Parameters(description = "name of the new html.") String name) throws IOException {
        Files.writeString(Path.of(name), blankHtml);
    }
}
