///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "text", mixinStandardHelpOptions = true, version = "text 0.1", description = "text util made with jbang")
class text {

    @Parameters(index = "0", description = "The greeting to print", defaultValue = "World!")
    private String greeting;

    public static void main(String... args) {
        int exitCode = new CommandLine(new text()).execute(args);
        System.exit(exitCode);
    }

    @Command(mixinStandardHelpOptions = true)
    void replaceBetween(@Parameters(description = "the file to replace", paramLabel = "file") Path file,
            @Option(names = {
                    "--start" }, paramLabel = "startLine", description = "the start line of content", required = true) String start,
            @Option(names = {
                    "--end" }, paramLabel = "endLine", description = "the end line of the content, if not provided same as start.") String end,
            @Option(names = {
                    "--dry-run" }, description = "dry run, do not write to file") boolean dryRun,
            @Option(names = {
                    "--keep-start-end" }, description = "keep the start and the end.") boolean keepTags,
            @Option(names = {
                    "--regex" }, description = "use regex to match the start and end") boolean isRegex,
            @Option(names = {
                    "--replace-with" }, paramLabel = "replacement", description = "the replacement string", required = true) String toReplace)
            throws IOException {

        List<String> lines = Files.readAllLines(file);
        List<String> afterChange = new ArrayList<>();
        end = end == null ? start : end;
        boolean startMet = false;
        boolean endMet = false;

        for (String line : lines) {
            boolean startMatchThisLine = startMet || (isRegex ? line.matches(start) : line.contains(start));
            boolean endMatchThisLine = startMet && (isRegex ? line.matches(end) : line.contains(end));

            if (!startMet && startMatchThisLine) {
                startMet = true;
                if (keepTags)
                    afterChange.add(line);
                continue;
            }

            if (!endMet && endMatchThisLine) {
                endMet = true;
                // insert replacement
                afterChange.add(toReplace);
                if (keepTags)
                    afterChange.add(line);
                continue;
            }

            if (startMet) {
                if (endMet) { // after endMet
                    afterChange.add(line);
                } else {
                    // skipping
                }
            } else {
                afterChange.add(line); // before startMet
            }
        }
        if (dryRun) {
            afterChange.stream().forEach(System.out::println);
        }
    }
}
