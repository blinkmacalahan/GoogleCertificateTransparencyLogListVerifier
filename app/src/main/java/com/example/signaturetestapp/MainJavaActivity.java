package com.example.signaturetestapp;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public class MainJavaActivity extends AppCompatActivity implements View.OnClickListener {

    public static final String TAG = "GoogleCertificateTransparencyLogListVerifier";

    public static final String UPPERCASE_WITH_SHA256_WITH_RSA = "SHA256WithRSA";

    public static final String LOWERCASE_SHA256_WITH_RSA = "SHA256withRSA";

    private TextView mTextView;

    private Button mUppercaseAlgorithm, mLowercaseAlgorithm;

    @Override
    protected void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mTextView = findViewById(R.id.text);
        mUppercaseAlgorithm = findViewById(R.id.uppercase);
        mLowercaseAlgorithm = findViewById(R.id.lowercase);

        mUppercaseAlgorithm.setOnClickListener(this);
        mLowercaseAlgorithm.setOnClickListener(this);
    }

    @Override
    public void onClick(final View v) {
        if (v == mUppercaseAlgorithm) {
            verifyLogList(UPPERCASE_WITH_SHA256_WITH_RSA);
        } else if (v == mLowercaseAlgorithm) {
            verifyLogList(LOWERCASE_SHA256_WITH_RSA);
        }
    }

    private void verifyLogList(final String algorithm) {
        try {
            final boolean result = isGoogleLogListVerified(MainJavaActivity.this, algorithm);
            mTextView.post(new Runnable() {
                @Override
                public void run() {
                    onVerificationComplete(result ? algorithm + ": Log List is Verified"
                            : algorithm + ": Log list FAILED verification");
                }
            });
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            mTextView.post(new Runnable() {
                @Override
                public void run() {
                    onVerificationComplete(
                            algorithm + ": Error while verifying log list.\n" + e.getMessage());
                }
            });
            e.printStackTrace();
        }
    }

    private void onVerificationComplete(final String displayText) {
        mTextView.setText(displayText);
    }

    public static boolean isGoogleLogListVerified(Context context, final String algorithm)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        byte[] sigBytes = toByteArray(context.getAssets().open("log_list.sig"));
        byte[] pubBytes = loadPEM(context.getAssets().open("log_list_pubkey.pem"));
        byte[] json = toByteArray(context.getAssets().open("log_list.json"));
        return isGoogleLogListVerified(algorithm, sigBytes, pubBytes, json);
    }

    public static boolean isGoogleLogListVerified(final String algorithm, byte[] signatureBytes, byte[] publicKeyBytes, byte[] logListBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            SignatureException {

        KeyFactory kf = KeyFactory.getInstance("RSA");
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
        sig.update(logListBytes);
        boolean verified = sig.verify(signatureBytes);
        return verified;
    }

    public static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        // read bytes from the input stream and store them in buffer
        while ((len = in.read(buffer)) != -1) {
            // write bytes from the buffer into output stream
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

    public static byte[] loadPEM(InputStream inputStream) throws IOException {
        byte[] pubBytes = toByteArray(inputStream);
        String pem = new String(pubBytes);
        Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
        String encoded = parse.matcher(pem).replaceFirst("$1");
        return Base64.getMimeDecoder().decode(encoded);
    }

    @Override
    public boolean onCreateOptionsMenu(final Menu menu) {
        super.onCreateOptionsMenu(menu);
        getMenuInflater().inflate(R.menu.menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull final MenuItem item) {
        if (item.getItemId() == R.id.kotlin) {
            startActivity(new Intent(this, MainActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
