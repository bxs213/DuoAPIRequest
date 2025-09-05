package com.duo.DuoAPIRequest;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;
import javax.crypto.Mac;

public class DuoRequest {
		
		private String date;
		private String method;
		private String host;
		private String path;
		private HashMap<String, String>  params;
		private ArrayList<String> encodedParameters;
		private String ikey;
		private String skey;
		
		public DuoRequest(String date,String method,String host,String path,HashMap<String, String> params, String IKEY, String SKEY) {
			this.date = date;
			this.method = method;
			this.host = host;
			this.path = path;
			this.params = params; 
			this.ikey = IKEY;
			this.skey = SKEY; 
			this.encodedParameters = parameterEncode();
		}

		public String sign() throws NoSuchAlgorithmException, InvalidKeyException {
			
			String HMACAlgorithm = "HmacSHA1";
			Mac mac = Mac.getInstance(HMACAlgorithm);
			byte[] hmacBytes;
			
			SecretKeySpec secret = new SecretKeySpec(skey.getBytes(), HMACAlgorithm);
			String auth = new String();
			ArrayList<String> canon = new ArrayList<String>();
			canon.add(date);
			canon.add(method);
			canon.add(host);
			canon.add(path);
			
			String canonString = new String();
			
			
			canon.add(String.join("&", encodedParameters));
			canonString = String.join("\n", canon);
		

			mac.init(secret);
			hmacBytes = mac.doFinal(canonString.getBytes());
			
			auth = ikey + ":" + HexFormat.of().formatHex(hmacBytes);
			
			return "Basic " + Base64.getEncoder().encodeToString(auth.getBytes());
			
		}
		
		public HttpResponse<String> request() throws InvalidKeyException, NoSuchAlgorithmException, IOException, InterruptedException  {
			String signedAuth = sign();
			String parameters = String.join("&", encodedParameters);
			
			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder request = HttpRequest.newBuilder()
					.uri(URI.create("https://" + host + path))
					.header("Date", date)
					.header("Authorization", signedAuth)
					.header("Content-Type", "application/x-www-form-urlencoded");

			if(method.equals("POST")) {
				request.POST(BodyPublishers.ofString(parameters));
			}
			 
			return client.send(request.build(),HttpResponse.BodyHandlers.ofString());
		}
		
		protected ArrayList<String> parameterEncode() {
			
			ArrayList<String> arguments = new ArrayList<String>();
			ArrayList<String> sortedKeys = new ArrayList<String>(params.keySet());
			Collections.sort(sortedKeys);
			
			for (String key : sortedKeys) {
				String encodedKey;
				String encodedValue;

				try {
					encodedKey = URLEncoder.encode(key, "UTF-8");
					encodedValue = URLEncoder.encode(params.get(key), "UTF-8");
					arguments.add(encodedKey + "=" + encodedValue);
					
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				}
				
			return arguments;	
		}
		
	}

