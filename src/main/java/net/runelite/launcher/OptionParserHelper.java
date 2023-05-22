package net.runelite.launcher;

import joptsimple.OptionParser;
import joptsimple.OptionSpec;

public class OptionParserHelper {
    public static OptionParser createOptionParser() {
        OptionParser parser = new OptionParser(false);
        parser.allowsUnrecognizedOptions();

        OptionSpec<Void> postInstallOption = parser.accepts("postinstall", "Perform post-install tasks");
        OptionSpec<Void> debugOption = parser.accepts("debug", "Enable debug logging");
        OptionSpec<Void> noDiffOption = parser.accepts("nodiff", "Always download full artifacts instead of diffs");
        OptionSpec<Void> skipTlsOption = parser.accepts("insecure-skip-tls-verification", "Disable TLS certificate and hostname verification");
        OptionSpec<String> scaleOption = parser.accepts("scale", "Custom scale factor for Java 2D").withRequiredArg();
        OptionSpec<Void> noUpdateOption = parser.accepts("noupdate", "Skips the launcher self-update");
        OptionSpec<Void> helpOption = parser.accepts("help", "Show this text (use --clientargs --help for client help)").forHelp();
        OptionSpec<String> classpathOption = parser.accepts("classpath", "Classpath for the client").withRequiredArg();
        OptionSpec<String> jvmOption = parser.accepts("J", "JVM argument (FORK or JVM launch mode only)").withRequiredArg();
        OptionSpec<Void> configureOption = parser.accepts("configure", "Opens configuration GUI");
        OptionSpec<LaunchMode> launchModeOption = parser.accepts("launch-mode", "JVM launch method (JVM, FORK, REFLECT)")
                .withRequiredArg()
                .ofType(LaunchMode.class);
        OptionSpec<HardwareAccelerationMode> hwAccelOption = parser.accepts("hw-accel", "Java 2D hardware acceleration mode (OFF, DIRECTDRAW, OPENGL, METAL)")
                .withRequiredArg()
                .ofType(HardwareAccelerationMode.class);
        OptionSpec<HardwareAccelerationMode> modeOption = parser.accepts("mode", "Alias of hw-accel")
                .withRequiredArg()
                .ofType(HardwareAccelerationMode.class);

        return parser;
    }
}

