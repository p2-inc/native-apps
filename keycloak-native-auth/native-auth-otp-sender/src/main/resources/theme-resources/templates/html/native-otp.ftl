<#-- spec/08 Q10: the one-time code mail of native-otp / native-verify-email (spec/03 §4.6, §4.13).
     Override by shipping html/native-otp.ftl in the realm's email theme. Variables: code, ttlMinutes,
     user, realmName, msg(...). The phrase "code is <digits>" is what the tests and the SDK's live
     tests parse; keep it when customising the demo. -->
<html>
<body>
<p>${msg("nativeOtpBodyHtml", code, ttlMinutes, realmName)?no_esc}</p>
</body>
</html>
