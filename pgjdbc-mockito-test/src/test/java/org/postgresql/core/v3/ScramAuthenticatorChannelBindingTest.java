/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.postgresql.core.PGStream;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Regression test for GHSA-j92g-9f8w-j867. Under {@code channelBinding=require}, the driver must
 * fail the connection rather than fall back to a non-PLUS mechanism when it cannot extract channel
 * binding data from the peer certificate. The test drives {@link ScramAuthenticator} over a mocked
 * TLS socket, so it needs no live server.
 */
class ScramAuthenticatorChannelBindingTest {

  @Test
  void requireRejectsCertificateWithoutChannelBindingHash() throws Exception {
    // A certificate whose signature algorithm yields no channel binding hash, such as Ed25519.
    // getSigAlgName is stubbed rather than parsing a real Ed25519 certificate: the JDK reports the
    // algorithm as the OID "1.3.101.112" on older JDK 11 builds and as "Ed25519" on newer ones, so
    // a parsed certificate would make the test JDK-version-dependent.
    X509Certificate cert = mock(X509Certificate.class);
    when(cert.getSigAlgName()).thenReturn("Ed25519");
    SSLSession session = mock(SSLSession.class);
    when(session.getPeerCertificates()).thenReturn(new Certificate[]{cert});
    SSLSocket socket = mock(SSLSocket.class);
    when(socket.getSession()).thenReturn(session);
    PGStream stream = mock(PGStream.class);
    when(stream.getSocket()).thenReturn(socket);

    PSQLException ex = assertThrows(PSQLException.class,
        () -> new ScramAuthenticator("secret".toCharArray(), stream, ChannelBinding.REQUIRE, 0));

    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), ex.getSQLState());
    // The message names the offending signature algorithm so an operator can act.
    assertTrue(ex.getMessage().contains("Ed25519"), ex.getMessage());
  }

  @Test
  void requireRejectsConnectionWithoutSsl() throws Exception {
    PGStream stream = mock(PGStream.class);
    when(stream.getSocket()).thenReturn(mock(Socket.class));

    PSQLException ex = assertThrows(PSQLException.class,
        () -> new ScramAuthenticator("secret".toCharArray(), stream, ChannelBinding.REQUIRE, 0));

    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), ex.getSQLState());
  }

  /**
   * When the TLS session exposes no X.509 peer certificate the driver has no channel binding data,
   * and the SCRAM library picks the advertised non-PLUS mechanism even though the server also
   * offers SCRAM-SHA-256-PLUS. Under {@code require} the negotiated mechanism must be rejected.
   */
  @Test
  void requireRejectsNegotiatedMechanismWithoutChannelBinding() throws Exception {
    PGStream stream = sslStream(mock(Certificate.class), "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256");

    PSQLException ex = assertThrows(PSQLException.class,
        () -> new ScramAuthenticator("secret".toCharArray(), stream, ChannelBinding.REQUIRE, 0));

    assertEquals(PSQLState.CONNECTION_REJECTED.getState(), ex.getSQLState());
    assertTrue(ex.getMessage().contains("does not use channel binding"), ex.getMessage());
  }

  /**
   * Control case for the test above: the same session under {@code prefer} still connects and
   * negotiates the non-PLUS mechanism, which is the downgrade {@code require} must refuse.
   */
  @Test
  void preferFallsBackToNonPlusMechanismWithoutChannelBinding() throws Exception {
    PGStream stream = sslStream(mock(Certificate.class), "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256");

    ScramAuthenticator authenticator =
        new ScramAuthenticator("secret".toCharArray(), stream, ChannelBinding.PREFER, 0);

    assertEquals("SCRAM-SHA-256", negotiatedMechanism(authenticator, stream));
  }

  /**
   * A certificate the driver can derive channel binding data from keeps working under
   * {@code require} and negotiates the PLUS mechanism.
   */
  @Test
  void requireNegotiatesPlusMechanismWithChannelBindingData() throws Exception {
    X509Certificate cert = mock(X509Certificate.class);
    when(cert.getSigAlgName()).thenReturn("SHA256withRSA");
    when(cert.getEncoded()).thenReturn(new byte[]{0x30, 0x03, 0x02, 0x01, 0x01});
    PGStream stream = sslStream(cert, "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256");

    ScramAuthenticator authenticator =
        new ScramAuthenticator("secret".toCharArray(), stream, ChannelBinding.REQUIRE, 0);

    assertEquals("SCRAM-SHA-256-PLUS", negotiatedMechanism(authenticator, stream));
  }

  /**
   * A mocked stream over a TLS socket presenting {@code peerCert} whose AuthenticationSASL body
   * advertises {@code mechanisms}.
   */
  private static PGStream sslStream(Certificate peerCert, String... mechanisms) throws Exception {
    SSLSession session = mock(SSLSession.class);
    when(session.getPeerCertificates()).thenReturn(new Certificate[]{peerCert});
    SSLSocket socket = mock(SSLSocket.class);
    when(socket.getSession()).thenReturn(session);
    PGStream stream = mock(PGStream.class);
    when(stream.getSocket()).thenReturn(socket);
    when(stream.receiveString()).thenReturn(mechanisms[0],
        Arrays.copyOfRange(mechanisms, 1, mechanisms.length));
    // A non-zero peek means another mechanism follows; the list ends with a NUL byte.
    Integer[] peeks = new Integer[mechanisms.length];
    Arrays.fill(peeks, (int) 'S');
    peeks[mechanisms.length - 1] = 0;
    when(stream.peekChar()).thenReturn(peeks[0], Arrays.copyOfRange(peeks, 1, peeks.length));
    return stream;
  }

  /**
   * Sends the SASLInitialResponse and returns the mechanism name the driver put on the wire,
   * which is the mechanism it really negotiated.
   */
  private static String negotiatedMechanism(ScramAuthenticator authenticator, PGStream stream)
      throws Exception {
    authenticator.handleAuthenticationSASL();
    ArgumentCaptor<byte[]> sent = ArgumentCaptor.forClass(byte[].class);
    verify(stream, atLeastOnce()).send(sent.capture());
    return new String(sent.getAllValues().get(0), StandardCharsets.UTF_8);
  }
}
