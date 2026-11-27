// Test fixture for sigma2joern. main() does nothing; the methods are never called.
import java.io.IOException;

public class Agent {
    private static final String CMD = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Agent /t REG_SZ /d C:\\ProgramData\\agent.exe /f";

    static void persist() throws IOException {
        Runtime.getRuntime().exec(CMD);
    }

    static void stage(String dir) throws IOException {
        new ProcessBuilder("powershell", "-ExecutionPolicy", "Bypass", "-File", dir + "\\stage2.ps1").start();
    }

    static String greet() {
        return new StringBuilder("Hello").toString();
    }

    public static void main(String[] args) { }
}
