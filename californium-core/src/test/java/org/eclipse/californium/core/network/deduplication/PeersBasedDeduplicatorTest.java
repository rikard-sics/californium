/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.KeyMID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.LoggerFactory;

@Category(Small.class)
public class PeersBasedDeduplicatorTest {

	private static final InetSocketAddress PEER = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5683);
	private static final int MESSAGES_PER_PEER = 4;
	private static final int NUMBER_OF_PEERS = 256;
	private static final int NUMBER_OF_MESSAGES = 512;

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	Configuration config;
	Deduplicator deduplicator;
	boolean intensiveLogging;

	@Before
	public void init() {
		config = new Configuration();
		config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
		config.set(CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES, MESSAGES_PER_PEER);
		config.set(CoapConfig.MARK_AND_SWEEP_INTERVAL, 1000, TimeUnit.MILLISECONDS);
		config.set(CoapConfig.DEDUPLICATOR_AUTO_REPLACE, true);
		deduplicator = DeduplicatorFactory.getDeduplicatorFactory().createDeduplicator(config);
		intensiveLogging = LoggerFactory.getLogger(SweepDeduplicator.class).isDebugEnabled();
	}

	@Test
	public void testLimitMessagesPerPeer() throws Exception {
		int mid = 10;

		Exchange previous = addExchange(mid);
		assertThat(previous, is(nullValue()));

		previous = addExchange(mid);
		assertThat(previous, is(notNullValue()));
		for (int loop = 0; loop < MESSAGES_PER_PEER * 16; ++loop) {
			previous = addExchange(++mid);
			assertThat(previous, is(nullValue()));
		}
		assertThat(deduplicator.size(), is(MESSAGES_PER_PEER));
		KeyMID key = new KeyMID(mid - 10, PEER);
		assertThat(deduplicator.find(key), is(nullValue()));
		key = new KeyMID(mid, PEER);
		assertThat(deduplicator.find(key), is(notNullValue()));

		// other peer
		previous = addExchange(++mid, new InetSocketAddress(InetAddress.getLoopbackAddress(), 5684));
		assertThat(previous, is(nullValue()));
		assertThat(deduplicator.size(), is(MESSAGES_PER_PEER + 1));
	}

	@Test
	public void testConcurrency() throws Exception {
		ScheduledExecutorService threadPool = ExecutorsUtil.newScheduledThreadPool(
				config.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT), new NamedThreadFactory("DedupTest#"));
		cleanup.add(threadPool);
		deduplicator.setExecutor(threadPool);
		deduplicator.start();
		InetAddress loopbackAddress = InetAddress.getLoopbackAddress();
		InetSocketAddress[] peers = new InetSocketAddress[NUMBER_OF_PEERS];
		for (int port = 0; port < NUMBER_OF_PEERS; ++port) {
			peers[port] = new InetSocketAddress(loopbackAddress, 5683 + port);
		}
		int numberOfExchanges = NUMBER_OF_PEERS * NUMBER_OF_MESSAGES;
		final CountDownLatch ready = new CountDownLatch(numberOfExchanges);
		Random random = new Random();
		for (int i = 0; i < numberOfExchanges; ++i) {
			final InetSocketAddress peer = peers[random.nextInt(NUMBER_OF_PEERS)];
			final int mid = random.nextInt(0x10000);
			threadPool.execute(new Runnable() {

				@Override
				public void run() {
					addExchange(mid, peer);
					ready.countDown();
				}
			});
		}
		assertThat(ready.await(intensiveLogging ? 30 : 10, TimeUnit.SECONDS), is(true));

		int size = deduplicator.size();
		assertThat(size, is(lessThanOrEqualTo(NUMBER_OF_PEERS * MESSAGES_PER_PEER)));

		long exchangeLifetime = config.get(CoapConfig.EXCHANGE_LIFETIME, TimeUnit.MILLISECONDS);
		int sweepInterval = config.getTimeAsInt(CoapConfig.MARK_AND_SWEEP_INTERVAL, TimeUnit.MILLISECONDS);
		time.setTestTimeShift(exchangeLifetime + 1000L, TimeUnit.MILLISECONDS);

		TestConditionTools.waitForCondition(exchangeLifetime, sweepInterval, TimeUnit.MILLISECONDS, () -> {
			return deduplicator.size() == 0;
		});
		int sizeAfterLifetime = deduplicator.size();
		assertThat(size + " exchanges", sizeAfterLifetime, is(0));
	}

	private Exchange addExchange(int mid) {
		return addExchange(mid, PEER);
	}

	private Exchange addExchange(int mid, InetSocketAddress peer) {
		Request incoming = Request.newGet();
		incoming.setMID(mid);
		incoming.setSourceContext(new AddressEndpointContext(peer));
		Exchange exchange = new Exchange(incoming, peer, Exchange.Origin.REMOTE, TestSynchroneExecutor.TEST_EXECUTOR);
		KeyMID key = new KeyMID(incoming.getMID(), peer);
		return deduplicator.findPrevious(key, exchange);
	}
}
