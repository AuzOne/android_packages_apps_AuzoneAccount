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

package com.auzone.account.auth;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import com.auzone.account.AuzoneAccount;
import com.auzone.account.R;
import com.auzone.account.util.AuzoneAccountUtils;

public class UpdateRequiredActivity extends Activity implements View.OnClickListener {
    private static final String TAG = UpdateRequiredActivity.class.getSimpleName();
    private Button mContinueButton;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.auzoneaccount_update_required);
        mContinueButton = (Button) findViewById(R.id.btn_continue);
        mContinueButton.setOnClickListener(this);
        AuzoneAccountUtils.hideNotification(this, AuzoneAccount.NOTIFICATION_ID_INCOMPATIBLE_VERSION);
    }

    @Override
    public void onClick(View view) {
        setResult(Activity.RESULT_OK);
        finish();
    }
}
