///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS org.json:json:20231013

import org.json.JSONObject;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "snapshot", mixinStandardHelpOptions = true, version = "snapshot 0.1", description = "snapshot made with jbang")
class snapshot {

        @Spec
        CommandSpec spec;

        public static void main(String... args) {
                int exitCode = new CommandLine(new command()).execute(args);
                System.exit(exitCode);
        }

        @Command(mixinStandardHelpOptions = true)
        void list(@Option(names = { "-n",
                        "--name" }, description = "filter by the name", paramLabel = "<partOfName>") String name,
                        @Option(names = { "-s",
                                        "--shared" }, arity = "0..1", description = "filter by the share") Boolean shared) {
                String myString = new JSONObject()
                                .put("name", name)
                                .put("shared", shared)
                                .toString();

                System.out.println(myString);
        }

        @Command(mixinStandardHelpOptions = true)
        void delete(@Parameters(description = "ID of the snapshot.", paramLabel = "<ID>") Long id,
                        @Option(names = {
                                        "--confirm" }, description = "add 'iknow' to confirm", paramLabel = "iknow", required = true) String confirm) {

                if (!"iknow".equals(confirm))
                        throw new ParameterException(spec.commandLine(),
                                        String.format("--confirm iknow"));

                String myString = new JSONObject()
                                .put("id", id)
                                .put("confirm", confirm)
                                .toString();
                System.out.println(myString);
        }

        @Command(mixinStandardHelpOptions = true)
        void create(@Parameters(description = "the name of the snapshot.", paramLabel = "name") String name,
                        @Option(names = { "-d",
                                        "--description" }, description = "A briefly description of the snapshot", paramLabel = "<Description>") String description,
                        @Option(names = { "-s",
                                        "--shared" }, description = "Make the snaphost public accessible") boolean shared,
                        @Option(names = {
                                        "--id" }, description = "If provided will overrride the snapshot specified by this id.", paramLabel = "NUMBER") Long id) {

                description = description == null ? "" : description;
                String myString = new JSONObject()
                                .put("name", name)
                                .put("description", description)
                                .put("shared", shared)
                                .put("id", id)
                                .toString();

                System.out.println(myString);
        }

        @Command(mixinStandardHelpOptions = true)
        void update(@Parameters(description = "the id of the snapshot.", paramLabel = "<ID>") Long id,
                        @Option(names = { "-d",
                                        "--description" }, description = "the briefly description of the snapshot", paramLabel = "Description") String description,
                        @Option(names = { "-s",
                                        "--shared" }, arity = "0..1", description = "make the snaphost public accessible, true,false, empty for not change. ", paramLabel = "Shared") Boolean shared,
                        @Option(names = {
                                        "-n",
                                        "--name" }, description = "the name of the snapshot", paramLabel = "Name") String name) {

                // throw new ParameterException(spec.commandLine(),
                // String.format("Invalid value '%s' for option '--prime': " +
                // "value is not a prime number.", "55"));
                // print the parsed parameters as a json object if all valid.
                // should handle the situation that description is null and description contains
                // "
                description = description == null ? "" : description;
                String myString = new JSONObject()
                                .put("name", name)
                                .put("description", description)
                                .put("shared", shared)
                                .put("id", id)
                                .toString();

                System.out.println(myString);
        }

}
