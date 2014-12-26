package com.gordon.scep.client;

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.KeyChain;
import android.view.Menu;
import android.view.View;
import android.widget.Spinner;
import android.widget.TextView;

public class MainActivity extends Activity {

	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	public void GenKey(View view) {

	
		TextView urI = (TextView) findViewById(R.id.ScepURL);
		CharSequence sURI = urI.getText();
		sURI.toString();

		Spinner iKeyLen = (Spinner) findViewById(R.id.spinner1);
		int isKeyLen = Integer.parseInt(String.valueOf(iKeyLen.getSelectedItem()));

		TextView tVCname = (TextView) findViewById(R.id.CommonName);
		TextView tVPassword = (TextView) findViewById(R.id.Password);

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

		try {
			byte[] keystore = ScepClient.CertReq(sURI.toString(), tVCname.getText().toString(), tVPassword.getText().toString(), isKeyLen);
			
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_CERTIFICATE, keystore);
			startActivity(intent);
			
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
