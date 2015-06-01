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

package com.auzone.account.ui;

import com.auzone.account.AuzoneAccount;
import com.auzone.account.R;
import com.auzone.account.auth.AuthActivity;
import com.auzone.account.auth.AuthClient;
import com.auzone.account.util.AuzoneAccountUtils;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

public class AuzoneAccountActivity extends Activity {

    private boolean mShowButtonBar;
    private boolean mIsImmersive;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mIsImmersive = getIntent().getBooleanExtra(AuzoneAccount.EXTRA_USE_IMMERSIVE, false);
        setContentView(R.layout.auzoneaccount_setup_standalone);
        ((TextView)findViewById(android.R.id.title)).setText(R.string.auzoneaccount_add_title);
        findViewById(R.id.existing_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AuthActivity.showForAuth(AuzoneAccountActivity.this,
                        AuzoneAccount.REQUEST_CODE_SETUP_AuzoneAccount,
                        mShowButtonBar, mIsImmersive);

            }
        });
        findViewById(R.id.new_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                /* DEPRECATED */
                // AuthActivity.showForCreate(AuzoneAccountActivity.this, AuzoneAccount.REQUEST_CODE_SETUP_AuzoneAccount);
                Toast.makeText(AuzoneAccountActivity.this,
                        R.string.auzoneaccount_deprecated, Toast.LENGTH_SHORT).show();

            }
        });
        findViewById(R.id.learn_more_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (!AuzoneAccountUtils.isNetworkConnected(AuzoneAccountActivity.this) ||
                        !AuzoneAccountUtils.isWifiConnected(AuzoneAccountActivity.this)) {
                    AuzoneAccountUtils.launchWifiSetup(AuzoneAccountActivity.this);
                } else {
                    AuzoneAccountUtils.showLearnMoreDialog(AuzoneAccountActivity.this);
                }
            }
        });
        mShowButtonBar = getIntent().getBooleanExtra(AuzoneAccount.EXTRA_SHOW_BUTTON_BAR, false);
        if (mShowButtonBar) {
            View buttonBar = findViewById(R.id.button_bar);
            buttonBar.setVisibility(View.VISIBLE);
            findViewById(R.id.prev_button).setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    setResult(RESULT_CANCELED);
                    finish();
                }
            });
            findViewById(R.id.next_button).setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    setResult(RESULT_FIRST_USER);
                    finish();
                }
            });
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mIsImmersive) {
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_IMMERSIVE
                    | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION);
        }
    }

    @Override
    public void finish() {
        super.finish();
        if (getIntent().getBooleanExtra(AuzoneAccount.EXTRA_FIRST_RUN, false)) {
            overridePendingTransition(R.anim.translucent_enter,
                    R.anim.translucent_exit);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == AuzoneAccount.REQUEST_CODE_SETUP_AuzoneAccount &&
                (resultCode == RESULT_OK || resultCode == RESULT_FIRST_USER)) {
            setResult(resultCode);
            finish();
        } else if (requestCode == AuzoneAccount.REQUEST_CODE_SETUP_WIFI) {
            if (resultCode == Activity.RESULT_OK ||
                    AuzoneAccountUtils.isNetworkConnected(AuzoneAccountActivity.this)) {
                AuzoneAccountUtils.showLearnMoreDialog(this);
            }
        }
    }
}