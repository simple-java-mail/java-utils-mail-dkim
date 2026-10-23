package org.simplejavamail.utils.mail.dkim;

import org.junit.jupiter.api.Test;
import java.io.File;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class ProviderNeutralClasspathTest {
    @Test
    void signsAndChecksDnsInAFreshJvmWithoutAngus() throws Exception {
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        List<String> retained = new ArrayList<String>();
        for (String entry : classpath.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
            if (!new File(entry).getName().startsWith("angus-")) { retained.add(entry); }
        }
        File log = new File("target/provider-neutral-classpath.log");
        Process process = new ProcessBuilder(new File(System.getProperty("java.home"), "bin/java").getPath(),
                "-classpath", String.join(File.pathSeparator, retained), "org.simplejavamail.dkim.consumer.ByteSigningConsumer")
                .redirectErrorStream(true).redirectOutput(log).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Provider-neutral consumer did not finish");
            String output = new String(Files.readAllBytes(log.toPath()), StandardCharsets.UTF_8);
            assertEquals(0, process.exitValue(), output);
        } finally {
            if (process.isAlive()) { process.destroyForcibly(); }
        }
    }
}
