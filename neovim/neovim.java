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
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "neovim", mixinStandardHelpOptions = true, version = "neovim 0.1", description = "an opinioned neovim configuration")
class neovim {

        // https://github.com/williamboman/mason-lspconfig.nvim/blob/main/doc/server-mapping.md
        String lspconfig = """
                        require("mason-lspconfig").setup {
                           -- ensure_installed = { "lua_ls","java_language_server" }
                            ensure_installed = { <<lss>> }
                        }
                        """;

        @Spec
        CommandSpec spec;

        public static void main(String... args) {
                int exitCode = new CommandLine(new neovim()).execute(args);
                System.exit(exitCode);
        }

        @Command(mixinStandardHelpOptions = true)
        void setup(@Parameters(description = "language servers to setup.", arity = "0..*", paramLabel = "<LanguageServers>") String[] languageServers)
                        throws IOException, InterruptedException {
                if (languageServers == null || languageServers.length == 0) {
                        languageServers = new String[] { "lua_ls" };
                }
                String lspconfig = this.lspconfig.replace("<<lss>>",
                                Stream.of(languageServers).map(this::quoteit).collect(Collectors.joining(",")));
                String url = "https://raw.githubusercontent.com/jianglibo/jbang-catalog/main/neovim/neovim.config.zip";
                
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(url))
                                .timeout(Duration.ofMinutes(1))
                                .GET()
                                .build();
                Path zipFile = Path.of("__neovim.config.zip");
                client.send(request, BodyHandlers.ofFile(zipFile));
                String script = """
                                if [[ ! ${HOME}/.config/nvim ]]; then
                                    mkdir -p ${HOME}/.config/nvim
                                fi
                                unzip -qo __neovim.config.zip -d nvim.config
                                if [[ $? -ne 0 ]]; then
                                    echo "unzip failed"
                                    exit 1
                                fi
                                echo "${lspconfig}" > nvim.config/.config/nvim/lua/config/mason-lspconfig.lua
                                cp -rf nvim.config/* ${HOME}/.config/nvim
                                rm -rf __neovim.config.zip
                                rm -rf nvim.config
                                """;
                MyLangUtil.runScript(script, Map.of("lspconfig", lspconfig)).stream().forEach(System.out::println);

        }

        private String quoteit(String origin) {
                return "\"" + origin + "\"";
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
