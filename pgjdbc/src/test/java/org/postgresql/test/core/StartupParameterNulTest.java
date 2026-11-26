/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.postgresql.PGProperty;
import org.postgresql.test.TestUtil;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

/**
 * The startup packet carries its parameters as NUL-terminated name/value pairs. A NUL inside a
 * user-supplied value would end that value early and smuggle the remainder in as further
 * parameters, and the server keeps the last assignment of a name. The driver must refuse such
 * values instead of sending them.
 */
class StartupParameterNulTest {
  /**
   * Appended to an otherwise valid value. Sent as is, the server would accept the connection and
   * apply the injected {@code application_name}.
   */
  private static final String INJECTION = "\0application_name\0nul_injected";

  @Test
  void validStartupParametersConnect() throws Exception {
    Properties props = new Properties();
    // application_name only travels in the startup packet when the server is assumed to be 9.0+
    PGProperty.ASSUME_MIN_SERVER_VERSION.set(props, "9.0");
    PGProperty.OPTIONS.set(props, "-c synchronous_commit=on");
    PGProperty.CURRENT_SCHEMA.set(props, "public");
    TestUtil.setTestUrlProperty(props, PGProperty.APPLICATION_NAME, "nul_test");

    try (Connection con = TestUtil.openDB(props);
         Statement stmt = con.createStatement();
         ResultSet rs = stmt.executeQuery("SHOW application_name")) {
      assertTrue(rs.next());
      assertEquals("nul_test", rs.getString(1));
    }
  }

  @Test
  void nulInUserIsRejected() {
    Properties props = new Properties();
    PGProperty.USER.set(props, TestUtil.getUser() + INJECTION);
    assertRejected(props, "user");
  }

  @Test
  void nulInDatabaseIsRejected() {
    Properties props = new Properties();
    TestUtil.setTestUrlProperty(props, PGProperty.PG_DBNAME, TestUtil.getDatabase() + INJECTION);
    assertRejected(props, "database");
  }

  @Test
  void nulInApplicationNameIsRejected() {
    Properties props = new Properties();
    PGProperty.ASSUME_MIN_SERVER_VERSION.set(props, "9.0");
    TestUtil.setTestUrlProperty(props, PGProperty.APPLICATION_NAME,
        "nul_test\0search_path\0nul_injected");
    assertRejected(props, "application_name");
  }

  @Test
  void nulInCurrentSchemaIsRejected() {
    Properties props = new Properties();
    PGProperty.CURRENT_SCHEMA.set(props, "public" + INJECTION);
    assertRejected(props, "search_path");
  }

  @Test
  void nulInOptionsIsRejected() {
    Properties props = new Properties();
    PGProperty.OPTIONS.set(props, "-c synchronous_commit=on" + INJECTION);
    assertRejected(props, "options");
  }

  @Test
  void nulInReplicationIsRejected() {
    Properties props = new Properties();
    PGProperty.ASSUME_MIN_SERVER_VERSION.set(props, "9.4");
    PGProperty.REPLICATION.set(props, "database" + INJECTION);
    assertRejected(props, "replication");
  }

  private static void assertRejected(Properties props, String parameter) {
    PSQLException e = assertThrows(PSQLException.class, () -> TestUtil.openDB(props).close(),
        "a NUL in the " + parameter + " startup parameter must abort the connection attempt");
    assertEquals(PSQLState.INVALID_PARAMETER_VALUE.getState(), e.getSQLState(),
        () -> "SQLState for NUL in " + parameter + ": " + e);
    String message = String.valueOf(e.getMessage());
    assertTrue(message.contains("startup parameter " + parameter) && message.contains("NUL"),
        () -> "the driver, not the server, must reject the NUL in " + parameter + ": " + e);
  }
}
