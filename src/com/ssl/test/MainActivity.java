package com.ssl.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import android.os.Bundle;
import android.app.Activity;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity
{
	LinearLayout tv;
	private Thread worker;
	private final String host = "google.com";
	private final int port = 443;
	private String[] sup_protocols = null;
	private String[] sup_ciphers = null;
	private final String[] sec_protocols = {"TLSv1.2", "TLSv1.1", "TLSv1"};
	private final String[] sec_ciphers = {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	"TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_256_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"};
	private static int pos = 0;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		tv = (LinearLayout) findViewById(R.id.t);
		worker = new Thread(new Runnable()
		{
			private void updateUI()
			{
				if (worker.isInterrupted())
					return;

				runOnUiThread(new Runnable()
				{
					@Override
					public void run()
					{
						if ((sup_protocols == null) || (sup_ciphers == null))
						{
							tv.removeAllViews();
							addTextView("Couldn't open SSLSocket for '" + host + "'. Is an internet connection available?");
						}
						else
						{
							String[] protocols = matchStringArr(sec_protocols, sup_protocols);
							String[] ciphers = matchStringArr(sec_ciphers, sup_ciphers);

							if (protocols.length > 0)
							{
								addTextView("Protocols:");
								for (String p : protocols)
									addTextView(p);
							}
							else
							{
								addTextView("none");
							}
							addTextView("");

							if (ciphers.length > 0)
							{
								addTextView("Cipher Suites:");
								for (String c : ciphers)
								{
									if (!c.equals("TLS_EMPTY_RENEGOTIATION_INFO_SCSV"))
										addTextView(c);
								}
							}
							else
							{
								addTextView("none");
							}
							addTextView("");

							if (ciphers[ciphers.length-1].equals("TLS_EMPTY_RENEGOTIATION_INFO_SCSV"))
								addTextView("Secure Client-Initiated Renegotiation supported.");
						}
					}
				});
			}

			@Override
			public void run()
			{
				try
				{
					SSLContext context = SSLContext.getInstance("TLS");
					context.init(null, null, new SecureRandom());
					SSLSocket socket = (SSLSocket)context.getSocketFactory().createSocket(host, port);
					sup_protocols = socket.getSupportedProtocols();
					sup_ciphers = socket.getSupportedCipherSuites();
					socket.close();
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
				updateUI();
			}
		});
		worker.start();
	}

	private void addTextView(String str)
	{
		TextView t = new TextView(MainActivity.this);
		t.setText(str);
		tv.addView(t, pos);
		pos++;
	}

	private static String[] matchStringArr(String[] a, String[] b)
	{
		List<String> list = new ArrayList<String>();
		for (int i=0; i<a.length; i++)
		{
			for (int j=0; j<b.length; j++)
			{
				if (a[i].equals(b[j]))
				{
					list.add(a[i]);
					break;
				}
			}
		}
		return list.toArray(new String[list.size()]);
	}
}
