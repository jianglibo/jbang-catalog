///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "download", mixinStandardHelpOptions = true, version = "download 0.1", description = "download assets from the internet or this project.")
class download implements Callable<Integer> {

    @Parameters(index = "0", description = "The staff to download, could be a url, a file in this project, or :all to download all.")
    private String toDownload;

    public static void main(String... args) {
        int exitCode = new CommandLine(new download()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        if (":all".equals(toDownload)) {
            String script = """
                    zip -qr __all.zip ./
                    """;
            MyLangUtil.runScript(script, null);
            System.out.println(prefixWithNoEffect(":download __all.zip"));
        } else if (Files.exists(Path.of(toDownload))) {
            System.out.println(prefixWithNoEffect(":download " + toDownload));
        } else {
            System.out.println("file " + toDownload + " doesn't exist.");
        }
        return 1;
    }

    private static final String NO_EFFECT_PATTERN = "\033[0m\033[0m\033[0m";

    private static String prefixWithNoEffect(String cmd) {
        return NO_EFFECT_PATTERN + cmd;
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

        public static List<String> runScript(String script, Map<String, String> extraEnvs) throws IOException {
            ProcessBuilder pb = new ProcessBuilder("/bin/bash")
                    .redirectErrorStream(true);
            Map<String, String> env = pb.environment();
            if (extraEnvs != null)
                env.putAll(extraEnvs);
            Process p = pb.start();
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
