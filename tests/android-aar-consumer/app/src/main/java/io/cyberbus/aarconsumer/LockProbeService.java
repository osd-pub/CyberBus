package io.cyberbus.aarconsumer;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ResultReceiver;
import java.io.File;
import java.io.IOException;
import io.cyberbus.sdk.DevelopmentFileStore;

/** Actual second ART process: exercises the AAR's OS lock, not its static JVM set. */
public final class LockProbeService extends Service {
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        ResultReceiver receiver = intent.getParcelableExtra("reply");
        Bundle result = new Bundle();
        result.putInt("pid", android.os.Process.myPid());
        try (DevelopmentFileStore ignored = DevelopmentFileStore.openExisting(new File(intent.getStringExtra("directory")))) {
            result.putBoolean("rejected", false);
        } catch (IOException expected) {
            boolean owned = false;
            for (Throwable cause = expected; cause != null; cause = cause.getCause())
                owned |= "Store already owned".equals(cause.getMessage());
            result.putBoolean("rejected", owned);
        } catch (Throwable failure) {
            result.putBoolean("unexpected", true);
        }
        receiver.send(0, result);
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
