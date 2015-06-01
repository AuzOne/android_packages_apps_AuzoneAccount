/*
 * Copyright (C) 2013 The auzone Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.auzone.account.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import com.auzone.account.AuzoneAccount;
import com.auzone.account.api.PingService;
import com.auzone.account.util.AuzoneAccountUtils;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = BootReceiver.class.getSimpleName();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent != null) {
            if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
                handleBootCompleted(context);
            }
        }
    }

    private void handleBootCompleted(Context context) {
        if (AuzoneAccount.DEBUG) Log.d(TAG, "Boot completed, scheduling ping");
        AuzoneAccountUtils.scheduleAuzoneAccountPing(context, PingService.getPingIntent(context));
    }
}
