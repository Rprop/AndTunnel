package rprop.net.tunnel;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private Button mStartButton;
    private Intent mService;
    private boolean mStarted = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        this.mService = new Intent(this, CoreService.class);
        this.mStartButton = findViewById(R.id.buttonStart);
        this.mStartButton.setOnClickListener(v -> {
            if (mStarted) {
                onActivityResult(0, RESULT_CANCELED, null);
            } else {
                final Intent intent = CoreService.prepare(MainActivity.this);
                if (intent != null) {
                    startActivityForResult(intent, 0);
                } else {
                    onActivityResult(0, RESULT_OK, null);
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        int resId;
        if (result == RESULT_OK) {
            this.mStarted = true;
            this.mStartButton.setText(R.string.btn_started);
            startService(this.mService);
            resId = R.string.run_started;
        } else {
            this.mStarted = false;
            this.mStartButton.setText(R.string.btn_start);
            CoreService.closeInterface();
            stopService(this.mService);
            resId = R.string.run_aborted;
        }
        Toast.makeText(this, resId, Toast.LENGTH_SHORT).show();
    }
}
