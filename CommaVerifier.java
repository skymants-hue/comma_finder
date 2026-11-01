package com.commafinder;

import android.content.Context;
import android.content.SharedPreferences;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * "이 IP가 진짜 comma 기기인가?"를 SSH 공개키 인증으로 확인한다.
 * 앱이 SSH 접속에 쓰는 것과 같은 키(user=comma)를 쓰므로,
 * 키가 등록되지 않은 헤드유닛/공유기/기타 기기는 인증 단계에서 탈락한다.
 *
 * 스캔 포트가 22든 7000이든 항상 22번 포트로 확인한다.
 */
public final class CommaVerifier implements PortScanner.Verifier {

    private static final int VERIFY_TIMEOUT_MS = 4000;

    private final String keyPath;

    private CommaVerifier(String keyPath) { this.keyPath = keyPath; }

    /** SshTerminalActivity.runSshConnection 과 같은 규칙으로 키 파일을 고른다. */
    public static CommaVerifier create(Context ctx) throws Exception {
        File custom = new File(ctx.getFilesDir(), "custom_id_rsa");
        File current = new File(ctx.getFilesDir(), "id_rsa_current");
        SharedPreferences sp = ctx.getSharedPreferences("CommaFinderPrefs", Context.MODE_PRIVATE);

        if (sp.getBoolean("use_custom_key", false) && custom.exists()) {
            return new CommaVerifier(custom.getAbsolutePath());
        }
        if (!current.exists()) {                       // 아직 SSH 한 번도 안 열었으면 assets 에서 복사
            try (InputStream in = ctx.getAssets().open("id_rsa.pem");
                 OutputStream out = new FileOutputStream(current)) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
        }
        return new CommaVerifier(current.getAbsolutePath());
    }

    @Override
    public boolean verify(String ip, int port) {
        Session session = null;
        try {
            JSch jsch = new JSch();
            jsch.addIdentity(keyPath);
            session = jsch.getSession("comma", ip, 22);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setConfig("PreferredAuthentications", "publickey");
            session.connect(VERIFY_TIMEOUT_MS);        // 인증 성공해야 예외 없이 통과
            return session.isConnected();
        } catch (Exception e) {
            return false;
        } finally {
            if (session != null) session.disconnect();
        }
    }
}
