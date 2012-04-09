/* decryptor.java loaded successfully! */

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import sun.misc.BASE64Decoder;

static Response response;
static HashMap safeSitesMap = new HashMap();
static HashMap decryptionKeyMap = new HashMap();
static final int CHUNKSIZE = 128;
static final String JSDELIMITER = "538W";

public Response fetchResponse(HTTPClient nextPlugin, Request request)
		throws IOException {
	
	// Get response
	response = nextPlugin.fetchResponse(request);
	
	// Don't mess with image data
	String contentType = response.getHeader("Content-Type");
	if (contentType.startsWith("image"))
		return response;
	
	// Get necessary req/resp details
	String referer = request.getHeader("referer");
	HttpUrl destination = request.getURL();
	String content = new String(response.getContent());
	
	// If refered, check if from response is from safe source
	if (referer != null) {
		ArrayList safeSites = (ArrayList)safeSitesMap.get(referer);
		// No safe sites means original request was not protected, so we can just return the refered resource
		if (safeSites == null)
			return response;
		// Otherwise check if host is allowed
		if (!safeSites.contains(destination.getHost()))
			return null;
	}
	
	// If not refered or refered and safe,
		// get the decryption key for the resource and the next chain of safe sites
	
	String decryptionKey = fetchResource(destination.getHost(), "/jsdefender_publickey.der");
	String safeSites = fetchResource(destination.getHost(), "/jsdefender_safesites");
	
	// If there is no decryption key, the resource is not protected so just return it
	if (decryptionKey == null)
		return response;
	
	decryptionKeyMap.put(destination.getHost(), decryptionKey);
	safeSitesMap.put(destination.getHost(), parseSafeSites(safeSites));
	
	// Modify the Content (perform decryption)
	
	String modContent = decryptTaggedResource(content);
	
	// Return the modified content
	
	byte[] byteContent = modContent.getBytes();
	response.setContent(byteContent);
	return response;
}

private ArrayList parseSafeSites(String safeSitesString) {
	ArrayList safeSites = new ArrayList(Arrays.asList(safeSitesString.split(",")));
	return safeSites;
}

private static String decryptTaggedResource(String resource) {
	Pattern matchEncrypted = Pattern.compile("(?m)(<" + JSDELIMITER + ">" + ".*?" + "</" + JSDELIMITER + ">)");
	String output = resource;
	Matcher matcher = matchEncrypted.matcher(output);
	while (matcher.find()) {
		String encrypted = matcher.group(0);
		output = output.replace("encrypted", decryptData(encrypted, "/home/lee/538w/publickey.der", CHUNKSIZE));
		matcher = matchEncrypted.matcher(output);
	}
	
	return output;
}

private static String fetchResource(String host, String path) {
	HttpClient httpClient = new DefaultHttpClient();
	String resource = null;
	try {
		URI resourceURL = URIUtils.createURI("http", host, -1, path, null, null);
		
		HttpGet resourceGet = new HttpGet(resourceURL);
		
		ResponseHandler responseHandler = new BasicResponseHandler();
		resource = (String)httpClient.execute(resourceGet, responseHandler);
	} catch (URISyntaxException e) {
		e.printStackTrace();
	} catch (ClientProtocolException e) {
		e.printStackTrace();
	} catch (IOException e) {
		e.printStackTrace();
	} finally {
		httpClient.getConnectionManager().shutdown();
	}
	
	return resource;
}

private static String decryptData(String encrypted, String keyPath, int chunkSize) {
	BASE64Decoder decoder = new BASE64Decoder();
	if (encrypted.startsWith("<" + JSDELIMITER + ">"))
		encrypted = encrypted.replaceFirst("<" + JSDELIMITER + ">", "");

	if (encrypted.endsWith("</" + JSDELIMITER + ">"))
		encrypted = encrypted.replace("</" + JSDELIMITER + ">", "");
	
	PublicKey publicKey = null;
	try {
		File pubkeyFile = new File(keyPath);
		FileInputStream fis = new FileInputStream(pubkeyFile);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[(int)pubkeyFile.length()];
	    dis.readFully(keyBytes);
	    dis.close();
	    
	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    
	    publicKey = kf.generatePublic(keySpec);
	} catch (Exception e) {
	    e.printStackTrace();
	} 

	Cipher publicChiper = null;
	String decryptedText = "";
	try {
	    publicChiper = Cipher.getInstance("RSA");
	    publicChiper.init(Cipher.DECRYPT_MODE, publicKey);
	    byte[] decodedMessage = decoder.decodeBuffer(encrypted);
	    int offset = 0;
	    while (offset < decodedMessage.length) {
	    	byte[] decrypted = publicChiper.doFinal(decodedMessage, offset, chunkSize);
	    	offset += chunkSize;
		    decryptedText += new String(decrypted);
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	return decryptedText;
}

