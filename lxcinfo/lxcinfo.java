///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS com.google.code.gson:gson:2.10.1
//DEPS ch.qos.reload4j:reload4j:1.2.19

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "lxcinfo", mixinStandardHelpOptions = true, version = "lxcinfo 0.1", description = "manage lxc.")
class lxcinfo {
    @Spec
    CommandSpec spec;

    static final Logger logger = Logger.getLogger(lxcinfo.class);

    private Gson gson;

    public lxcinfo() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Date.class, new LastUsedAtDeserializer());
        gson = gsonBuilder.create();
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new lxcinfo()).execute(args);
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.ERROR);
        logger.info("Welcome to jbang");
        System.exit(exitCode);
    }

    @Command(mixinStandardHelpOptions = true, description = "list all containers")
    void list() {
        ProcessRunnerSync processRunner = ProcessRunnerSync.ofCmds("lxc", "list", "--format", "json");
        ProcessRunnerSync.ProcessOutput output = processRunner.run();

        Type containerListType = new TypeToken<List<LxcContainer>>() {
        }.getType();

        List<LxcContainer> lxcContainers = gson.fromJson(output.purifyContent(), containerListType);

        Collections.sort(lxcContainers, (c1, c2) -> c1.getLastUsedAt().compareTo(c2.getLastUsedAt()));
        Collections.reverse(lxcContainers);

        if (output.success()) {
            System.out.println(gson.toJson(lxcContainers));
        } else {
            System.out.println(output.purifyContent());
        }
    }

    @Command(mixinStandardHelpOptions = true, name = "switch", description = "swith to another runenv. UNSAVED CHANGES WILL BE LOST.")
    void switchTo(@Parameters(description = "ID of the runenv.", paramLabel = "<ID>") Long id,
            @Option(names = {
                    "--confirm" }, description = "add 'iknow' to confirm", paramLabel = "iknow", required = true) String confirm) {

        if (!"iknow".equals(confirm))
            throw new ParameterException(spec.commandLine(),
                    String.format("--confirm iknow"));

        System.out.println(gson.toJson(Map.of("id", id, "confirm", confirm)));
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

    public static record CommonErrorItem(String name, String message) {

    }

    static record ManageItem(String id, Map<String, Object> data) {
    }

    // /**
    // * default action: index
    // */
    // public static record ManageInstructor(DemoVmToWorker vm, String action,
    // List<ManageItem> item) {
    // }

    /**
     * {items: [{id: "id", data: {name: "name", status: "status"}}], actions:
     * ["action1", "action2"]}
     */

    public static record ManageResponse(List<ManageItem> items, List<String> actions) {
    }

    public static class CommonResponseObjectBody<T> {
        private T data;
        private List<CommonErrorItem> errors;

        public CommonResponseObjectBody(T data) {
            this.data = data;
        }

        public CommonResponseObjectBody(CommonErrorItem error) {
            this.errors = List.of(error);
        }

        public CommonResponseObjectBody(String name, String message) {
            this.errors = List.of(new CommonErrorItem(name, message));
        }

        public String errorsToString() {
            if (errors == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            for (CommonErrorItem e : errors) {
                sb.append(e.toString());
                sb.append("\n");
            }
            return sb.toString();
        }

    }

    public static class LxcContainer {
        private String name;
        private String status;

        // @SerializedName("last_used_at")
        @SerializedName("last_used_at")
        private Date lastUsedAt;
        // private String last_used_at;

        /**
         * @return the lastUsedAt
         */
        public Date getLastUsedAt() {
            return lastUsedAt;
        }

        /**
         * @param lastUsedAt the lastUsedAt to set
         */
        public void setLastUsedAt(Date lastUsedAt) {
            this.lastUsedAt = lastUsedAt;
        }

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @param name the name to set
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * @return the status
         */
        public String getStatus() {
            return status;
        }

        /**
         * @param status the status to set
         */
        public void setStatus(String status) {
            this.status = status;
        }

    }

    public static class ProcessRunnerSync {

        /**
         * If running a script, the sudo won't take effect.
         */
        private Map<String, String> envs = new HashMap<>();
        private List<String> cmds;

        private boolean sudo;
        private String script;
        private String asUser;

        private Duration waitTime;

        private boolean notRedirectError;

        private boolean notMute = false;

        private boolean debug;

        private volatile boolean stopReading = false;

        private List<String> outputs = new ArrayList<>();

        private Process p;
        private Path workingDir;

        public ProcessRunnerSync proxy(String proxy) {
            envs.put("https_proxy", proxy);
            return this;
        }

        public static ProcessRunnerSync ofCmds(String... cmds) {
            ProcessRunnerSync r = new ProcessRunnerSync();
            r.cmds = List.of(cmds);
            return r;
        }

        /**
         * sudo -S -E -u appuser003 /bin/bash
         */
        private void createProcess() throws IOException {
            if (script != null) {
                ProcessBuilder processBuilder;
                if (sudo) {
                    if (asUser == null) {
                        processBuilder = new ProcessBuilder("sudo", "-S", "-E", "/bin/bash");
                    } else {
                        processBuilder = new ProcessBuilder("sudo", "-S", "-E", "-u", asUser, "/bin/bash");
                    }
                } else {
                    processBuilder = new ProcessBuilder("/bin/bash");
                }
                // = sudo ? (asUser == null ? new ProcessBuilder("sudo", "-S", "-E",
                // "/bin/bash")
                // : new ProcessBuilder("sudo", "-S", "-E", "-u", asUser, "/bin/bash"))
                // : new ProcessBuilder("/bin/bash");
                decoProcessBuilder(processBuilder);
                p = processBuilder.start();
            } else {
                ProcessBuilder processBuilder = new ProcessBuilder(cmds);
                decoProcessBuilder(processBuilder);
                p = processBuilder.start();
            }
        }

        private void decoProcessBuilder(ProcessBuilder processBuilder) {
            if (workingDir != null) {
                processBuilder.directory(workingDir.toFile());
            }
            processBuilder.environment().putAll(envs);
            processBuilder.redirectErrorStream(!notRedirectError);
        }

        private void preprocessCmds() {
            if (script == null && !cmds.contains("sudo") && sudo) {
                // insert 'sudo' at the index 0 of the cmds;
                // cmds may immutable
                cmds = new ArrayList<>(cmds);
                cmds.add(0, "sudo"); // cmds is immutable.
            }
        }

        public ProcessOutput run() {
            preprocessCmds();
            try {
                String message = script == null ? String.format("About to run: %s", String.join(" ", cmds))
                        : "About to run a multiple line script. ";
                if (notMute) {
                    outputs.add(message);
                }
                createProcess();
                // Start a separate thread to read the process output
                if (notMute) {
                    outputs.add("processRunner pid: " + p.pid() + " start at: " + p.info().startInstant());
                }
                if (script != null) {
                    new Thread(() -> {
                        try {
                            OutputStream os = p.getOutputStream();
                            os.write(script.getBytes(StandardCharsets.UTF_8));
                            os.flush();
                            os.close();
                        } catch (IOException e) {
                            ;
                        }
                    }).start();
                }
                readProcessOutput(p);
                try {
                    p.waitFor();
                } catch (Exception e) {
                }
                int pexitCode = p.exitValue();
                int exitCode = outputs.stream().filter(line -> line.startsWith("exitCode:")).findFirst()
                        .map(line -> Integer.parseInt(line.split(":", 2)[1].trim())).orElse(pexitCode);
                return ProcessOutput.of(exitCode, outputs);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private void readProcessOutput(Process process) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while (!stopReading && (line = reader.readLine()) != null) {
                    outputs.add(line);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public static class ProcessOutput {

            List<String> lines;
            int exitCode = 0; // better to 0 for default.

            public static final String OUTPUT_BEGIN = "----output begin----";
            public static final String OUTPUT_END = "----output end----";

            public static ProcessOutput of(int exitCode, List<String> lines) {
                ProcessOutput output = new ProcessOutput();
                output.lines = lines;
                output.exitCode = exitCode;
                return output;
            }

            public String purifyContent() {
                return String.join("\n", purifyLines());
            }

            public List<String> purifyLines() {
                // content between output begin and output end
                // better to find the line contains these two fags.
                if (lines == null) {
                    return List.of();
                }
                int begin = 0;
                for (String line : lines) {
                    begin++;
                    if (line.contains(OUTPUT_BEGIN)) {
                        break;
                    }
                }
                int end = 0;
                for (String line : lines) {
                    end++;
                    if (line.contains(OUTPUT_END)) {
                        break;
                    }
                }
                if (begin < end) {
                    return lines.subList(begin, end - 1);
                } else {
                    return lines;
                }

            }

            public List<String> linesWithoutExitCodeLineNotImmutable() {
                return new ArrayList<>(linesWithoutExitCodeLine());
            }

            public List<String> linesWithoutExitCodeLine() {
                if (lines == null) {
                    return List.of();
                }
                return lines.stream().filter(line -> !line.startsWith("exitCode:")).toList();
            }

            public boolean success() {
                return exitCode == 0;
            }
        }

    }

    class LastUsedAtDeserializer implements JsonDeserializer<Date> {
        private static final SimpleDateFormat ISO8601_FORMAT = new SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'");

        @Override
        public Date deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            try {
                return ISO8601_FORMAT.parse(json.getAsString());
            } catch (ParseException e) {
                throw new JsonParseException("Error parsing ISO 8601 date-time string", e);
            }
        }
    }

}
