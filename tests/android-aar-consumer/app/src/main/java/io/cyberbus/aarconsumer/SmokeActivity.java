package io.cyberbus.aarconsumer;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class SmokeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("Frozen public AAR: ART/JNI consumer smoke");
        setContentView(view);
    }
}
