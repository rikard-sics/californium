/*******************************************************************************
 * Copyright (c) 2020 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.oscore.federated;

import java.io.FileWriter;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.Collections;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpContentResponse;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.api.Result;
import org.eclipse.jetty.client.util.BufferingResponseListener;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.eclipse.jetty.client.util.StringContentProvider;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory.Client.SniProvider;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

/**
 * Test sender configured to support multicast requests. Rebased.
 */
@SuppressWarnings("deprecation")
public class GrpcClient {

	/**
	 * Maximum message size
	 */
	private static int MAX_MSG_SIZE = 1400;

	/**
	 * Maximum time to wait for replies when using unicast (one by one)
	 */
	private static final int UNICAST_TIMEOUT = 30000;

	/**
	 * Ratio of servers that need to have responded for the client to stop
	 * listening at the check points
	 */
	private static final double SERVER_RESPONSE_RATIO = 0.8;

	/**
	 * Time to wait before checking for the first time if responses from 80%
	 * of the servers have been received (parallel unicast).
	 */
	private static final int CHECK1_TIMEOUT = 15000;

	/**
	 * Time to wait before checking for the second time if responses from 80%
	 * of the servers have been received (parallel unicast).
	 */
	private static final int CHECK2_TIMEOUT = 22000;

	/**
	 * Maximum time to wait for replies when using parallel unicast.
	 */
	private static final int FINAL_TIMEOUT = UNICAST_TIMEOUT;

	/**
	 * Whether to use gRPC or not.
	 */
	static boolean useGrpc = true;

	/**
	 * Use unicast one-by-one to the servers
	 */
	static boolean unicastMode = true;

	/**
	 * Use unicast but send requests to all servers in parallel (with a small
	 * delay between each send to avoid overloading the medium) instead of
	 * waiting for each server's response before contacting the next one.
	 * Requires unicastMode to also be enabled.
	 */
	static boolean parallelUnicastMode = false;

	/**
	 * Delay in milliseconds between sending unicast requests to consecutive
	 * servers when using parallel unicast.
	 */
	private static final long PARALLEL_UNICAST_SEND_DELAY_MS = 5;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static InetAddress multicastIP = CoAP.MULTICAST_IPV4;
	static InetAddress multicastIP;

	/**
	 * Resource to perform request against.
	 */
	static String requestResource = "/model";

	private static List<INDArray> models = new ArrayList<>();
	private static int MAX_GLOBAL_EPOCHS;
	private static int modelsize = 0;

	// For early stopping
	private static int epochsNoImprovement = 0;
	private final static float CONTINUE_TRESHOLD = 0.005f;
	private final static int NO_IMPROVEMENT_EPOCHS = 5;
	private static boolean stopEarly = false;

	// Variables for storing experimental results
	private static List<Long> epochTimes = new ArrayList<Long>();
	private static Map<String, long[]> rtts = new HashMap<>();
	private static HashMap<String, Float> accuracies = new HashMap<String, Float>();
	private static Map<String, float[]> storedAccuracies = new HashMap<>();

	// For controlling aggregation and model version
	private static int latestModelVersion = -1;
	private static int AGGREGATION_THRESHOLD;
	private static boolean didAggregation = true;
	private static HashMap<String, Boolean> sentInitialRequest = new HashMap<String, Boolean>();

	private static int serverCount;
	private static String serverDataset;
	private static List<String> unicastServerIps;

	// For gRPC
	private static boolean useTls = false;
	private static String scheme;
	private static int port;
	private static HttpClient httpClient;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String args[]) throws Exception {

		long start = System.nanoTime();

		// Parse command line arguments
		HashMap<String, String> cmdArgs = new HashMap<>();

		for (int i = 0; i < args.length; i += 2) {

			if (i + 1 >= args.length) {
				continue;
			}

			if (args[i + 1].toLowerCase().equals("null")) {
				;
			} else {
				cmdArgs.put(args[i], args[i + 1]);
			}
		}

		if (cmdArgs.containsValue("--help")) {
			printHelp();
		}

		serverCount = -1;
		boolean useFederatedLearning = true;
		boolean debugPrint = true;
		boolean sendMultiKill = false;
		try {
			serverCount = Integer.parseInt(cmdArgs.get("--server-count"));
			useFederatedLearning = Boolean.parseBoolean(cmdArgs.getOrDefault("--federated-learning", "true"));
			useGrpc = Boolean.parseBoolean(cmdArgs.getOrDefault("--grpc", "true"));
			useTls = Boolean.parseBoolean(cmdArgs.getOrDefault("--tls", "false"));
			unicastMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--unicast", "true"));
			parallelUnicastMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--parallel-unicast", "false"));
			MAX_GLOBAL_EPOCHS = Integer.parseInt(cmdArgs.getOrDefault("--max-epochs", "100"));
			debugPrint = Boolean.parseBoolean(cmdArgs.getOrDefault("--debug", "true"));
			modelsize = Integer.parseInt(cmdArgs.getOrDefault("--model-size", "-1"));
			serverDataset = cmdArgs.get("--server-data");
			sendMultiKill = Boolean.parseBoolean(cmdArgs.getOrDefault("--send-multi-kill", "false"));
		} catch (Exception e) {
			printHelp();
		}

		if (!debugPrint) {
			DebugOut.ENABLE_PRINTING = false;
		}

		if (serverCount == -1) {
			printHelp();
		}

		if (useGrpc && !unicastMode) {
			DebugOut.println("Invalid config:");
			DebugOut.println("useGprc: " + useGrpc);
			DebugOut.println("unicastMode: " + unicastMode);
			DebugOut.println();
			printHelp();
		}

		if (parallelUnicastMode && !unicastMode) {
			DebugOut.println("Invalid config:");
			DebugOut.println("parallelUnicastMode: " + parallelUnicastMode);
			DebugOut.println("unicastMode: " + unicastMode);
			DebugOut.println();
			printHelp();
		}

		// Parse list of IPs for the servers
		unicastServerIps = new ArrayList<String>();
		if (unicastMode) {
			Pattern ipv4Pattern = Pattern
					.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
			Pattern ipv6Pattern = Pattern.compile("\\A(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\z");

			for (int i = 0; i < args.length; i++) {
				if (ipv4Pattern.matcher(args[i]).matches()) {
					unicastServerIps.add(args[i]);
				}
				if (ipv6Pattern.matcher(args[i]).matches()) {
					unicastServerIps.add(args[i]);
				}
				if (args[i].contains(":")) {
					unicastServerIps.add(args[i]);
				}

			}
		}

		// End parse command line arguments

		// === Start HTTP client
		if (useTls) {
			scheme = "https";
			port = 5080;
		} else {
			scheme = "http";
			port = 5080;
		}

		ClientConnector connector = new ClientConnector();

		SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
		sslContextFactory.setTrustAll(true);
		sslContextFactory.setSNIProvider(SniProvider.NON_DOMAIN_SNI_PROVIDER);
		if (useTls) {
			connector.setSslContextFactory(sslContextFactory);
		}

		// Low-level HTTP/2 engine
		HTTP2Client http2Client = new HTTP2Client(connector);

		// Transport that speaks HTTP/2
		HttpClientTransportOverHTTP2 transport = new HttpClientTransportOverHTTP2(http2Client);

		// Create and start the Jetty HttpClient
		httpClient = new HttpClient(transport);

		httpClient.getContentDecoderFactories().clear(); // No gzip?

		httpClient.start();
		// === End start HTTP client

		// Set threshold for doing aggregation (ceil 40%)
		AGGREGATION_THRESHOLD = (int) Math.ceil(serverCount * 0.40);

		// Information about the sender
		DebugOut.println("==================");
		DebugOut.println("*Sender");
		DebugOut.println("Uses gRPC: " + useGrpc);
		DebugOut.println("Use multicast: " + !unicastMode);
		DebugOut.println("Request destination: " + "List of unicast IPs provided");
		DebugOut.println("Request destination port: " + port);
		DebugOut.println("Outgoing port: " + "Dynamic");
		DebugOut.println("Use TLS: " + useTls);
		DebugOut.println("Total server count: " + serverCount);
		DebugOut.println("Max epochs: " + MAX_GLOBAL_EPOCHS);
		DebugOut.println("Expected model size: " + modelsize);
		DebugOut.println("Use federated learning: " + useFederatedLearning);

		if (unicastMode) {
			DebugOut.println("Unicast Server IPs: ");
			for (int i = 0; i < unicastServerIps.size(); i++) {
				DebugOut.println(unicastServerIps.get(i));
			}
		}
		DebugOut.println("==================");

		byte[] prevPayloadReq = null;

		int currentEpoch = 0;
		for (int i = 0; i < MAX_GLOBAL_EPOCHS && stopEarly == false; i++) {

			currentEpoch = i;
			long epochStart = System.nanoTime();

			DebugOut.println("=== Communication Epoch: " + i + " ===");

			if (currentEpoch % 25 == 0) {
				System.out.println("@epoch: " + currentEpoch);
			}

			float[] modelReq = new float[0];

			byte[] payloadReq;
			if (i == 0) {
				payloadReq = new byte[0];

				// Append version number to payload
				latestModelVersion++;
				byte[] tempArray = Arrays.copyOf(payloadReq, payloadReq.length + 1);
				tempArray[tempArray.length - 1] = (byte) latestModelVersion;
				payloadReq = Arrays.copyOf(tempArray, tempArray.length);

			} else {

				// If there are more received responses
				if (models.size() > 1) {

					INDArray avgModel = getAverage(models, modelsize);
					modelReq = avgModel.toFloatVector();

				} else if (models.size() == 1) {
					// If there is only one model in the buffer list
					modelReq = models.get(0).toFloatVector();
				} else {
					DebugOut.errPrintln("Error: No model received");
				}

				// Ensure that the model to be sent is valid
				boolean invalidModel = false;
				if (modelReq == null || modelReq.length != modelsize) {
					invalidModel = true;
				}

				if (!didAggregation) {
					DebugOut.errPrintln("Not sending latest model since aggregation was not done!");
				}
				if (invalidModel) {
					DebugOut.errPrintln("Not sending latest model since it is invalid!");
				}

				// Build byte payload to send from float vector
				if (didAggregation == true && invalidModel == false) {
					payloadReq = FloatConverter.floatVectorToBytes(modelReq);
					prevPayloadReq = Arrays.copyOf(payloadReq, payloadReq.length);
					latestModelVersion++;
				} else {
					// Send previous model
					payloadReq = Arrays.copyOf(prevPayloadReq, prevPayloadReq.length);
				}

				// Error checking model size
				if (modelReq.length != modelsize) {
					DebugOut.errPrintln("Invalid model size when sending!");
					DebugOut.errPrintln("Expected model size: " + modelsize + " but sending: " + modelReq.length);
				}

				// Append version number to payload
				byte[] tempArray = Arrays.copyOf(payloadReq, payloadReq.length + 1);
				tempArray[tempArray.length - 1] = (byte) latestModelVersion;
				payloadReq = Arrays.copyOf(tempArray, tempArray.length);

				DebugOut.print("Outgoing request payload: ");
				for (int j = 0; j < modelReq.length; j++) {
					DebugOut.print(modelReq[j] + " ");
				}
				if (payloadReq.length > MAX_MSG_SIZE) {
					DebugOut.errPrintln("Error: Payload exceeds maximum messages size (" + MAX_MSG_SIZE + " bytes)");
				}

				models.clear();

			}

			List<ContentResponse> responses = new ArrayList<ContentResponse>(serverCount);

			// Either send unicast requests to all servers in parallel, loop
			// and send unicast requests one by one, or send 1 multicast
			if (unicastMode && parallelUnicastMode) {

				responses.clear();
				MultiHttpHandler handler = new MultiHttpHandler(serverCount);
				Collections.shuffle(unicastServerIps);

				for (int n = 0; n < unicastServerIps.size(); n++) {

					boolean useEmptyPayload = false;

					// Empty payload for servers being contacted first time
					byte[] emptyPayload = new byte[0];

					// Append version number to payload
					byte[] tempArray2 = Arrays.copyOf(emptyPayload, emptyPayload.length + 1);
					tempArray2[tempArray2.length - 1] = (byte) latestModelVersion;
					emptyPayload = Arrays.copyOf(tempArray2, tempArray2.length);

					// Use empty request for servers not yet contacted
					if (sentInitialRequest.containsKey(unicastServerIps.get(n)) == false
							|| sentInitialRequest.get(unicastServerIps.get(n)) == false) {
						useEmptyPayload = true;
						sentInitialRequest.put(unicastServerIps.get(n), true);
					} else {
						useEmptyPayload = false;
					}

					// Send request using gRPC

					// Perform a GET request over HTTP/2
					httpClient.setUserAgentField(new HttpField(HttpHeader.USER_AGENT, "grpc-java-netty/1.69.1"));

					final String targetUri = scheme + "://[" + unicastServerIps.get(n) + "]:" + port
							+ "/helloworld.Greeter/SayHello";
					Request req = httpClient.POST(targetUri);
					req.header("content-type", "application/grpc");
					req.header("grpc-accept-encoding", "gzip");
					req.header("te", "trailers");
					req.timeout(UNICAST_TIMEOUT, TimeUnit.MILLISECONDS);
					req.idleTimeout(UNICAST_TIMEOUT, TimeUnit.MILLISECONDS);

					BytesContentProvider myCont;
					if (useEmptyPayload == false) {
						myCont = new BytesContentProvider(payloadReq);
					} else {
						myCont = new BytesContentProvider(emptyPayload);
					}
					req.content(myCont);

					// Prepare to save RTT
					final String serverRid = req.getHost();
					if (!rtts.containsKey(serverRid)) {
						rtts.put(serverRid, new long[MAX_GLOBAL_EPOCHS]);
						Arrays.fill(rtts.get(serverRid), -1);
					}

					DebugOut.println("Sending request to: " + targetUri);
					final long sendStartNanos = System.nanoTime();
					req.send(new BufferingResponseListener() {
						@Override
						public void onComplete(Result result) {
							if (result.isFailed()) {
								DebugOut.println("Request failed for " + targetUri + ": " + result.getFailure());
								return;
							}

							long rttNanos = System.nanoTime() - sendStartNanos;
							ContentResponse response = new HttpContentResponse(result.getResponse(), getContent(),
									getMediaType(), getEncoding());

							DebugOut.println("Status: " + response.getStatus());
							DebugOut.println("Response: " + response.getContentAsString());

							handler.onResponse(response, serverRid, rttNanos);
						}
					});

					// Small delay before contacting the next server, to avoid
					// overloading the medium with simultaneous sends
					if (n < unicastServerIps.size() - 1) {
						try {
							Thread.sleep(PARALLEL_UNICAST_SEND_DELAY_MS);
						} catch (InterruptedException e) {
							//
						}
					}
				}

				handler.waitOn(FINAL_TIMEOUT);

				for (Map.Entry<String, Long> entry : handler.getRttNanosByHost().entrySet()) {
					rtts.get(entry.getKey())[currentEpoch] = entry.getValue();
				}
				responses.addAll(handler.getResponses());

			} else if (unicastMode) {

				responses.clear();
				Collections.shuffle(unicastServerIps);

				for (int n = 0; n < unicastServerIps.size(); n++) {

					boolean useEmptyPayload = false;

					// Empty payload for servers being contacted first time
					byte[] emptyPayload = new byte[0];

					// Append version number to payload
					byte[] tempArray2 = Arrays.copyOf(emptyPayload, emptyPayload.length + 1);
					tempArray2[tempArray2.length - 1] = (byte) latestModelVersion;
					emptyPayload = Arrays.copyOf(tempArray2, tempArray2.length);

					// Stop if sufficient servers have responded this epoch
					if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
						break;
					}

					// Use empty request for servers not yet contacted
					if (sentInitialRequest.containsKey(unicastServerIps.get(n)) == false
							|| sentInitialRequest.get(unicastServerIps.get(n)) == false) {
						useEmptyPayload = true;
						sentInitialRequest.put(unicastServerIps.get(n), true);
					} else {
						useEmptyPayload = false;
					}

					// Send request using gRPC

					// Perform a GET request over HTTP/2
					httpClient.setUserAgentField(new HttpField(HttpHeader.USER_AGENT, "grpc-java-netty/1.69.1"));

					String targetUri = scheme + "://[" + unicastServerIps.get(n) + "]:" + port
							+ "/helloworld.Greeter/SayHello";
					Request req = httpClient.POST(targetUri);
					req.header("content-type", "application/grpc");
					req.header("grpc-accept-encoding", "gzip");
					req.header("te", "trailers");
					req.timeout(UNICAST_TIMEOUT, TimeUnit.MILLISECONDS);
					req.idleTimeout(UNICAST_TIMEOUT, TimeUnit.MILLISECONDS);

					BytesContentProvider myCont;
					if (useEmptyPayload == false) {
						myCont = new BytesContentProvider(payloadReq);
					} else {
						myCont = new BytesContentProvider(emptyPayload);
					}
					req.content(myCont);

					// Prepare to save RTT
					String serverRid = req.getHost();
					if (!rtts.containsKey(serverRid)) {
						rtts.put(serverRid, new long[MAX_GLOBAL_EPOCHS]);
						Arrays.fill(rtts.get(serverRid), -1);
					}

					ContentResponse response = null;
					long rttNanos = -1;
					DebugOut.println("Sending request to: " + targetUri);
					try {
						long sendStartNanos = System.nanoTime();
						response = req.send();
						rttNanos = System.nanoTime() - sendStartNanos;

						if (response == null) {
							continue;
						}
					} catch (TimeoutException e) {
						DebugOut.println("Timed out waiting for response from " + targetUri);
						continue;
					} catch (Exception e) {
						DebugOut.println("Request failed for " + targetUri + ": " + e.getMessage());
						continue;
					}

					responses.add(response);

					rtts.get(serverRid)[currentEpoch] = rttNanos;

					DebugOut.println("Status: " + response.getStatus());
					DebugOut.println("Response: " + response.getContentAsString());

					// End send request using gRPC

				}

			}

			// Print received responses
			if (responses.size() == 0) {

				DebugOut.errPrintln("ERROR: No Response from servers.");

			}

			boolean toBeContinued = false;
			// Ensure to continue if no responses were received this epoch
			if (responses == null || responses.size() == 0) {
				toBeContinued = true;
				didAggregation = false;
			}

			for (int j = 0; j < responses.size(); j++) {
				ContentResponse resp = responses.get(j);

				DebugOut.println("=== Response " + (j + 1) + " ===");
				DebugOut.println("Response from from: " + resp.getRequest().getHost());

				// Error checking
				if (resp.getContent().length < 400) {
					DebugOut.println("Ignoring error or insufficiently small message from server");
					DebugOut.println(" === ");
					DebugOut.println("Payload: " + resp.getContentAsString());
					DebugOut.println(" === ");
					continue;
				}

				// Parse and handle response
				DebugOut.println(resp.getContentAsString());

				// Parse bytes in response payload into float vector
				byte[] payloadRes = resp.getContent();
				float[] modelResPre = FloatConverter.bytesToFloatVector(payloadRes);

				// Error checking of model size
				if (modelsize != (modelResPre.length - 1)) {
					DebugOut.errPrintln("Invalid model size received! Ignoring response.");
					DebugOut.errPrintln("Expected model size: " + modelsize + " but received: " + modelResPre.length);
					continue;
				}

				// Retrieve Recipient ID of the server
				String serverRid = resp.getRequest().getHost();

				// Save received bytes and RTT
				if (!rtts.containsKey(serverRid)) {
					rtts.put(serverRid, new long[MAX_GLOBAL_EPOCHS]);
					Arrays.fill(rtts.get(serverRid), -1);
				}

				// rtts.get(serverRid)[currentEpoch] =
				// resp.advanced().getApplicationRttNanos();

				// Check for early stopping
				float serverAccuracy = modelResPre[modelResPre.length - 1];
				float lastAccuracy = accuracies.getOrDefault(serverRid, 0f);
				if (serverAccuracy < 0.9 || serverAccuracy - lastAccuracy > CONTINUE_TRESHOLD) {
					toBeContinued = true;
				}
				accuracies.remove(serverRid);
				accuracies.put(serverRid, serverAccuracy);

				// Save accuracies form the servers
				if (!storedAccuracies.containsKey(serverRid)) {
					storedAccuracies.put(serverRid, new float[MAX_GLOBAL_EPOCHS]);
					Arrays.fill(storedAccuracies.get(serverRid), -1);
				}
				storedAccuracies.get(serverRid)[currentEpoch] = serverAccuracy;
				float[] modelRes = new float[modelResPre.length - 1];
				System.arraycopy(modelResPre, 0, modelRes, 0, modelResPre.length - 1);

				DebugOut.println();

				DebugOut.print("Incoming payload in response: ");
				for (int k = 0; k < modelRes.length; k++) {
					DebugOut.print(modelRes[k] + " ");

				}

				if (responses.size() < AGGREGATION_THRESHOLD) {
					// Do not aggregate
					didAggregation = false;
				} else {
					INDArray model = Nd4j.create(modelRes);
					DebugOut.println("Received model size: " + model.length());
					models.add(model);
					didAggregation = true;
				}

			}

			// Check early stopping criteria
			if (epochsNoImprovement >= NO_IMPROVEMENT_EPOCHS) {
				DebugOut.print("Early stopping criteria fulfilled");
				stopEarly = true;
			}

			if (toBeContinued == true) {
				epochsNoImprovement = 0;
			} else {
				// Only count as epoch of no improvement if aggregation happened
				if (didAggregation == true) {
					epochsNoImprovement++;
				}
			}

			long epochEnd = System.nanoTime();
			long epochTotal = epochEnd - epochStart;
			epochTimes.add(epochTotal);

		}

		long finish = System.nanoTime();
		long timeElapsed = finish - start;

		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmm");
		String dateString = now.format(formatter);
		String newl = System.getProperty("line.separator");

		/** Write results to file **/
		FileWriter myWriter = new FileWriter(dateString + "-grpc-" + serverDataset + "-" + serverCount + "-res.txt");
		myWriter.write("Cumulative TCP payload data sent (bytes): " + "See separate .cap file" + newl);
		myWriter.write("Cumulative TCP payload data received (bytes): " + "See separate .cap file" + newl);
		myWriter.write("Time until stop condition (ns): " + timeElapsed + newl);
		myWriter.write("Number of epochs: " + (currentEpoch + 1) + newl + newl);

		myWriter.write("Times for each epoch" + newl);
		for (int i = 0; i < epochTimes.size(); i++) {
			myWriter.write(i + " " + epochTimes.get(i) + newl);
		}
		myWriter.write(newl);

		myWriter.write("RTT" + newl);
		myWriter.write("ID # ns" + newl);
		for (Map.Entry<String, long[]> entry : rtts.entrySet()) {
			String serverId = entry.getKey();
			long[] rttArray = entry.getValue();

			for (int i = 0; i < rttArray.length; i++) {
				String val = Long.toString(rttArray[i]);

				if (rttArray[i] == -1) {
					val = "N/A";
				}

				myWriter.write(serverId + " " + i + " " + val + newl);
			}
		}
		myWriter.write(newl);

		myWriter.write("Server Accuracy" + newl);
		myWriter.write("ID # acc" + newl);
		for (Map.Entry<String, float[]> entry : storedAccuracies.entrySet()) {
			String serverId = entry.getKey();
			float[] accuracyArray = entry.getValue();

			for (int i = 0; i < accuracyArray.length; i++) {
				String val = String.format("%.12f", accuracyArray[i]);

				if (accuracyArray[i] == -1) {
					val = "N/A";
				}

				myWriter.write(serverId + " " + i + " " + val + newl);
			}
		}
		myWriter.write(newl);

		myWriter.close();

		// Kill servers and close client
		if (sendMultiKill) {
			for (int i = 0; i < 30; i++) {
				sendServerKillMsg();
				Thread.sleep(500);
			}
		}
		System.exit(0);
	}

	private static void sendServerKillMsg() {
		for (int n = 0; n < unicastServerIps.size(); n++) {

			// Send request using gRPC

			// Perform a GET request over HTTP/2
			httpClient.setUserAgentField(new HttpField(HttpHeader.USER_AGENT, "grpc-java-netty/1.69.1"));

			String targetUri = scheme + "://[" + unicastServerIps.get(n) + "]:" + port + "/helloworld.Greeter/SayHello";
			Request req = httpClient.POST(targetUri);
			req.header("content-type", "application/grpc");
			req.header("grpc-accept-encoding", "gzip");
			req.header("te", "trailers");

			BytesContentProvider myCont;
			myCont = new StringContentProvider("EXIT123");
			req.content(myCont);

			DebugOut.println("Sending kill request to: " + targetUri);
			ContentResponse response = null;
			try {
				response = req.send();
			} catch (InterruptedException | TimeoutException | ExecutionException e) {
				// Normal as the server will be killed
				// System.err.println("Failed to send kill message to server: "
				// + unicastServerIps.get(n));
				// e.printStackTrace();
			}

			if (response != null) {
				DebugOut.println("Status: " + response.getStatus());
				DebugOut.println("Response: " + response.getContentAsString());
			}

			// End send request using gRPC
		}
	}

	public static INDArray getAverage(List<INDArray> list, int modelsize) {

		INDArray avg = Nd4j.zeros(modelsize);
		for (int i = 0; i < list.size(); i++) {
			INDArray arr = list.get(i);
			DebugOut.println("Model:" + arr);
			avg = avg.add(arr);
		}

		avg = avg.div(list.size());
		DebugOut.println("Updated Model:" + avg);

		return avg;
	}

	/**
	 * Handler for sending requests to all servers in parallel and collecting
	 * their responses. Mirrors the CoAP/OSCORE client's MultiCoapHandler:
	 * waitOn() waits in three phases (CHECK1_TIMEOUT / CHECK2_TIMEOUT /
	 * FINAL_TIMEOUT), checking after each phase whether more than
	 * SERVER_RESPONSE_RATIO of the servers have responded, and returns once
	 * that holds, once all servers have responded, or the final timeout is
	 * reached.
	 */
	private static class MultiHttpHandler {

		private final int interval1 = CHECK1_TIMEOUT;
		private final int interval2 = CHECK2_TIMEOUT - CHECK1_TIMEOUT;
		private final int interval3 = FINAL_TIMEOUT - CHECK2_TIMEOUT;

		private final List<ContentResponse> responses = new ArrayList<ContentResponse>();
		private final Map<String, Long> rttNanosByHost = new HashMap<>();
		private boolean on;
		private final int serverCount;
		private boolean keepWaiting = true;

		public MultiHttpHandler(int serverCount) {
			this.serverCount = serverCount;

			if (interval1 <= 0 || interval2 <= 0 || interval3 <= 0) {
				DebugOut.errPrintln("error: invalid wait intervals in handler");
				throw new IllegalArgumentException("Invalid wait intervals in handler");
			}
		}

		public synchronized List<ContentResponse> getResponses() {
			return responses;
		}

		public synchronized Map<String, Long> getRttNanosByHost() {
			return rttNanosByHost;
		}

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {

				// First waiting period (split into parts of 10 to stop early
				// if enough responses are received)
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval1 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

				// Second waiting period
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval2 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

				// Final waiting period
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval3 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

			} catch (InterruptedException e) {
				//
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		/**
		 * Record a received response. Only touches this handler's own
		 * synchronized state (never the static rtts/accuracies/models
		 * fields), since this runs on Jetty's I/O threads, concurrently with
		 * the main thread still sending requests to other servers.
		 */
		public synchronized void onResponse(ContentResponse response, String serverRid, long rttNanos) {
			on();
			responses.add(response);
			rttNanosByHost.put(serverRid, rttNanos);

			// Stop waiting once all servers have responded
			if (responses.size() == serverCount) {
				keepWaiting = false;
			}
		}
	}

	private static void printHelp() {
		System.out.println("Arguments: ");
		System.out.println("--server-count: Total number of servers [Mandatory.]");
		System.out.println("--model-size: The size of the model. [Mandatory.]");
		System.out.println("--federated-learning: Use Federated Learning [Optional. Default: true]");
		System.out.println("--multicast-ip: IPv4 or IPv6 [Optional. Default: ipv4]");
		System.out.println("--grpc: Use gRPC [Optional. Default: true]");
		System.out.println("--tls: Use TLS (for gRPC) [Optional. Default: false]");
		System.out.println("--unicast: Use unicast one-by-one to the servers [Optional. Default: true]");
		System.out.println(
				"--parallel-unicast: Use unicast but send requests to all servers in parallel [Optional. Default: false]");
		System.out.println("--max-epochs: Stop the training after this many epochs [Optional. Default: 100]");
		System.out.println("--debug: Enable/disable debug printing [Optional. Default: true]");
		System.out.println("--server-data: Dataset for this server [IoT, SD, Diabetes] (only for logging)");
		System.out.println("--send-multi-kill: Send multiple kill messages to the servers [Optional. Default: false]");
		System.exit(1);
	}

}
