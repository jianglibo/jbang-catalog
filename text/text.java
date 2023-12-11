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
                    "--debug" }, description = "echo the parameters") boolean debug,
            @Option(names = {
                    "--replace-with" }, paramLabel = "replacement", description = "the replacement string", required = true) String toReplace)
            throws IOException {

        if (debug) {
            System.out.println("file: " + file);
            System.out.println("start: " + start);
            System.out.println("end: " + end);
            System.out.println("dryRun: " + dryRun);
            System.out.println("keepTags: " + keepTags);
            System.out.println("isRegex: " + isRegex);
            System.out.println("toReplace: " + toReplace);
        }
        end = end == null ? start : end;

        ReplaceResult afterChange = replace(file, start, end, keepTags, isRegex, toReplace);
        if (!afterChange.changed) {
            String trimQuoteStart = trimQuotes(start);
            String trimQuoteEnd = trimQuotes(end);
            if (trimQuoteStart != null && trimQuoteEnd != null) {
                afterChange = replace(file, trimQuoteStart, trimQuoteEnd, keepTags, isRegex, toReplace);
            }
        }
        if (!afterChange.changed) {
            System.out.println("No change");
            return;
        }
        if (dryRun) {
            afterChange.lines.stream().forEach(System.out::println);
        } else {
            Files.write(file, afterChange.lines);
        }
    }

    private String trimQuotes(String str) {
        if (str.startsWith("'") && str.endsWith("'")) {
            return str.substring(1, str.length() - 1);
        } else if (str.startsWith("\"") && str.endsWith("\"")) {
            return str.substring(1, str.length() - 1);
        }
        return null;
    }

    private static class ReplaceResult {
        public List<String> lines;
        public boolean changed;

        public static ReplaceResult of(List<String> lines, boolean changed) {
            ReplaceResult result = new ReplaceResult();
            result.lines = lines;
            result.changed = changed;
            return result;
        }
    }

    private ReplaceResult replace(Path file, String start, String end, boolean keepTags, boolean isRegex,
            String toReplace) throws IOException {
        List<String> lines = Files.readAllLines(file);
        List<String> afterChange = new ArrayList<>();
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
        return ReplaceResult.of(afterChange, startMet && endMet);
    }
}
