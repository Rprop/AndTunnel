package rprop.net.tunnel;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public final class CoreService extends VpnService {
    private static final String TAG = "AndTunnelService";
    private static int sNativeFd = 0;

    static {
        System.loadLibrary("tunnel");
    }

    public static native void transferIpPackage(int fd, Object vpn);

    public static native void closeFd(int fd);

    @Override
    public int onStartCommand(final Intent intent, final int flags, final int startId) {
        Log.d(TAG, "onStartCommand");

        final ParcelFileDescriptor descriptor = new CoreService.Builder()
                .setSession(TAG)
                .setMtu(65535)
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                // .addRoute("139.224.51.62", 32)
                // .addRoute("114.114.115.115", 32)
                .addDnsServer("114.114.115.115")
                .establish();
        if (descriptor == null) {
            Log.e(TAG, "Not prepared");
            return START_NOT_STICKY;
        }

        sNativeFd = descriptor.detachFd();
        transferIpPackage(sNativeFd, this);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");

        closeInterface();
    }

    public static void closeInterface() {
        Log.d(TAG, "closeInterface");

        if (sNativeFd != 0) {
            closeFd(sNativeFd);
            sNativeFd = 0;
        }
    }

    //2022-08-04 17:39:16.858 13812-14824/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112793, ack 0, 'syn', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.886 13812-14825/rprop.net.tunnel I/AndTunnel: [TCP] 14.215.177.38:443 -> 10.0.0.1:46226, seq 0, ack 598112794, 'synack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.886 13812-14826/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112794, ack 1, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.887 13812-14827/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112794, ack 1, 'pshack', windows 65535, tcp payload 180
    //2022-08-04 17:39:16.888 13812-14827/rprop.net.tunnel I/AndTunnel: [TCP] 14.215.177.38:443 -> 10.0.0.1:46226, seq 0, ack 598112974, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.889 13812-14828/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112974, ack 1, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.901 13812-14829/rprop.net.tunnel I/AndTunnel: [TCP] 14.215.177.38:443 -> 10.0.0.1:46226, seq 0, ack 598112974, 'ack', windows 65535, tcp payload 1452
    //2022-08-04 17:39:16.902 13812-14830/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112974, ack 1452, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.903 13812-14831/rprop.net.tunnel I/AndTunnel: [TCP] 14.215.177.38:443 -> 10.0.0.1:46226, seq 1452, ack 598112974, 'ack', windows 65535, tcp payload 3817
    //2022-08-04 17:39:16.904 13812-14832/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112974, ack 5269, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.918 13812-14833/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112974, ack 5269, 'pshack', windows 65535, tcp payload 7
    //2022-08-04 17:39:16.918 13812-14834/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112981, ack 5269, 'rstack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.920 13812-14833/rprop.net.tunnel I/AndTunnel: [TCP] 14.215.177.38:443 -> 10.0.0.1:46226, seq 5269, ack 598112981, 'ack', windows 65535, tcp payload 0
    //2022-08-04 17:39:16.921 13812-14835/rprop.net.tunnel I/AndTunnel: [TCP] 10.0.0.1:46226 -> 14.215.177.38:443, seq 598112981, ack 0, 'rst', windows 0, tcp payload 0
}
