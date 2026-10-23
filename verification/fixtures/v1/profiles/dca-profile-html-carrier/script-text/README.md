# HTML script-text writer case

This draft, independently hand-authored case is passive JSON input for the
selected HTML-writer contract. It has no cryptographic capture provenance and
makes no claim about signatures or decryption. `AAAA` is opaque canonical
base64url carrier text. The unknown delivery member must survive serialization.

`input.dcaData` is the data-carrier value; `input.sealedContent` is the
sealed-content carrier array. The strings combine a mixed-case closing-script
prefix, a complete closing tag, and the HTML script double-escape transition
`<!--<script>`. A writer that escapes slashes alone loses the following carrier
or page sentinel when a scripting-enabled HTML document parser reads its output.

Expected results are semantic equality of both decoded JSON values, exactly one
body carrier of each reserved class, and the intact following page sentinel.
There is no required JSON or HTML spelling, member order, or escape convention.
The `base-contract` manifest consumer identifies the shared selector machinery;
the target is explicitly selected HTML-carrier evidence, not issuer admission.
