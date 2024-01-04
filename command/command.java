///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS org.json:json:20231013

import org.json.JSONObject;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "command", mixinStandardHelpOptions = true, version = "command 0.1", description = "command made with jbang")
class command {

        @Spec
        CommandSpec spec;

        public static void main(String... args) {
                int exitCode = new CommandLine(new command()).execute(args);
                System.exit(exitCode);
        }

        @Command(mixinStandardHelpOptions = true)
        void list(
                        @Option(names = { "-n",
                                        "--name" }, description = "filter by the name", paramLabel = "<partOfName>") String name,
                        @Option(names = { "-m",
                                        "--my" }, description = "list only my commands", paramLabel = "<My>") boolean my,
                        @Option(names = { "-p",
                                        "--page" }, description = "page number", paramLabel = "PageNumber", defaultValue = "0") int page,
                        @Option(names = {
                                        "--pp" }, description = "per page", paramLabel = "PerPage", defaultValue = "10") int pp) {
                if (pp > 100) {
                        pp = 100;
                }
                String myString = new JSONObject()
                                .put("name", name)
                                .put("page", page)
                                .put("pp", pp)
                                .put("my", my)
                                .toString();
                System.out.println(myString);
        }

        @Command(mixinStandardHelpOptions = true)
        void show(@Parameters(description = "id of the command.", paramLabel = "<ID>") Long id) {
                String myString = new JSONObject()
                                .put("id", id)
                                .toString();
                System.out.println(myString);
        }

}
