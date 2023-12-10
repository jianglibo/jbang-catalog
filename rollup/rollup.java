///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "rollup", mixinStandardHelpOptions = true, version = "rollup 0.1", description = "rollup boilerplate made with jbang")
class rollup {

    public static void main(String... args) {
        int exitCode = new CommandLine(new rollup()).execute(args);
        System.exit(exitCode);
    }

    @Command(mixinStandardHelpOptions = true)
    void simple(
            @Parameters(description = "name of the project.", paramLabel = "<name>", defaultValue = "test-rollup") String name)
            throws IOException, InterruptedException {
        String url = "https://raw.githubusercontent.com/jianglibo/jbang-catalog/main/rollup/rollup.zip";
        Path projectRoot = Path.of(name);
        if (!Files.exists(projectRoot)) {
            Files.createDirectories(projectRoot);
        }
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMinutes(1))
                // .header("Content-Type", "application/json")
                // .POST(BodyPublishers.ofFile(Paths.get("file.json")))
                .GET()
                .build();
        Path zipFile = projectRoot.resolve("__rollup.zip");
        client.send(request, BodyHandlers.ofFile(zipFile));
        String script = """
                cd {{projectRoot}}
                unzip -o __rollup.zip
                if [[ $? -ne 0 ]]; then
                    echo "unzip failed"
                    exit 1
                fi
                rm -rf __rollup.zip
                """;
        script = script.replace("{{projectRoot}}", projectRoot.toAbsolutePath().toString());
        MyLangUtil.runScript(script).stream().forEach(System.out::println);
        // print out usage, please cd to the project root. run npm install and npm run dev, and live-server public
        // wrap the printed content with a squar.

        System.out.println("what to do next:");
        System.out.println("------------------------------------------------------------------------");
        System.out.println("cd " + projectRoot.toAbsolutePath().toString());
        System.out.println("npm install");
        System.out.println("npm run dev");
        System.out.println("live-server public");
        System.out.println("------------------------------------------------------------------------");

    }

    public static class MyLangUtil {
        private static Pattern argPattern = Pattern.compile("\"([^\"]*)\"|'([^']*)'|(\\S+)");

        public static List<String> runCmd(String cmd) throws IOException {
            return new BufferedReader(new InputStreamReader(
                    new ProcessBuilder(splitArgs(cmd))
                            .redirectErrorStream(true)
                            .start()
                            .getInputStream()))
                    .lines().toList();
        }

        public static List<String> runScript(String script) throws IOException {
            Process p = new ProcessBuilder("/bin/bash")
                    .redirectErrorStream(true).start();
            OutputStream os = p.getOutputStream();
            os.write(script.getBytes(StandardCharsets.UTF_8));
            os.flush();
            os.close();
            List<String> lines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            } catch (IOException e) {
            }
            return lines;
        }

        public static String[] splitArgs(String argsLine) {
            Matcher matcher = argPattern.matcher(argsLine);
            List<String> args = new ArrayList<>();

            while (matcher.find()) {
                if (matcher.group(1) != null) {
                    args.add(matcher.group(1));
                } else if (matcher.group(2) != null) {
                    args.add(matcher.group(2));
                } else {
                    args.add(matcher.group(3));
                }
            }

            // find last index of item which starts with - or -- in the args
            int lastIndexOfOption = -1;
            for (int i = args.size() - 1; i >= 0; i--) {
                String arg = args.get(i);
                if (arg.startsWith("-")) {
                    lastIndexOfOption = i;
                    break;
                }
            }
            // if last index isn't the last second index, then combine all items behind the
            // last index
            if (lastIndexOfOption != -1 && lastIndexOfOption < args.size() - 2) {
                int lastIndexOfValue = lastIndexOfOption + 1;
                StringBuilder sb = new StringBuilder();
                for (int i = lastIndexOfValue; i < args.size(); i++) {
                    sb.append(args.get(i)).append(" ");
                }
                args.set(lastIndexOfValue, sb.toString().trim());
                for (int i = args.size() - 1; i > lastIndexOfValue; i--) {
                    args.remove(i);
                }
            }
            return args.toArray(i -> new String[i]);
        }
    }
}
