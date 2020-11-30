/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/

package org.eclipse.californium.edhoc;

import java.nio.charset.Charset;

/**
 * Constants for use with the EDHOC protocol.
 * 
 * @author Marco Tiloca and Rikard Höglund
 *
 */
public class Constants {

/**
 * Charset for this library
 */
public static final Charset charset = Charset.forName("UTF-8");
	

/**
 * Content-Format application/edhoc
 */
public static final int APPLICATION_EDHOC = 10001;


/**
 * EDHOC authentication methods
 * 
 * +-------+---------------+---------------+
 * | Value | Initiator     | Responder     |
 * +-------+---------------+---------------|
 * |   0   | Signature Key | Signature Key |
 * |   1   | Signature Key | Static DH Key |
 * |   2   | Static DH Key | Signature Key |
 * |   3   | Static DH Key | Static DH Key |
 * +-------+---------------+---------------+
 * 
 */

public static final int EDHOC_AUTH_METHOD_0 = 0;
public static final int EDHOC_AUTH_METHOD_1 = 2;
public static final int EDHOC_AUTH_METHOD_2 = 2;
public static final int EDHOC_AUTH_METHOD_3 = 3;


/**
 * EDHOC correlation methods
 * 
 * +-------+-------------------------------------------+
 * | Value | Description                               |
 * +-------+-------------------------------------------+
 * |   0   | No message correlation is possible        |
 * |   1   | Correlation between Message1 and Message2 |
 * |   2   | Correlation between Message2 and Message3 |
 * |   3   | Full message correlation is possible      |
 * +-------+-------------------------------------------+
 * 
 */

public static final int EDHOC_CORR_METHOD_0 = 0;
public static final int EDHOC_CORR_METHOD_1 = 2;
public static final int EDHOC_CORR_METHOD_2 = 2;
public static final int EDHOC_CORR_METHOD_3 = 3;


/**
 * EDHOC cipher suites
 * 
 * Value: 0
 * Array: 10, 5, 4, -8, 6, 10, 5
 * Desc: AES-CCM-16-64-128, SHA-256, X25519, EdDSA, Ed25519,
 *       AES-CCM-16-64-128, SHA-256
   
 * Value: 1
 * Array: 30, 5, 4, -8, 6, 10, 5
 * Desc: AES-CCM-16-128-128, SHA-256, X25519, EdDSA, Ed25519,
 *       AES-CCM-16-64-128, SHA-256

 * Value: 2
 * Array: 10, 5, 1, -7, 1, 10, 5
 * Desc: AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256,
 *       AES-CCM-16-64-128, SHA-256

 * Value: 3
 * Array: 30, 5, 1, -7, 1, 10, 5
 * Desc: AES-CCM-16-128-128, SHA-256, P-256, ES256, P-256,
 *       AES-CCM-16-64-128, SHA-256
 * 
 */

public static final int EDHOC_CIPHER_SUITE_0 = 0;
public static final int EDHOC_CIPHER_SUITE_1 = 1;
public static final int EDHOC_CIPHER_SUITE_2 = 2;
public static final int EDHOC_CIPHER_SUITE_3 = 3;


/**
 * EDHOC protocol steps
 * 
 */

// Initiator steps
public static final int EDHOC_BEFORE_M1 = 0; // Before sending EDHOC Message 1
public static final int EDHOC_AFTER_M1 = 1;  // After sending EDHOC Message 1

// Responder steps
public static final int EDHOC_BEFORE_M2 = 2; // Before sending EDHOC Message 2
public static final int EDHOC_AFTER_M2 = 3;  // After sending EDHOC Message 2

// Common steps
public static final int EDHOC_AFTER_M3 = 4;  // After sending EDHOC Message 3

}
