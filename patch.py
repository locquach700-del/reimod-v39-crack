import os, glob, sys, re

print("[*] REIMOD V39 crack")

def replace_method(path, sig, body):
    with open(path) as f:
        c = f.read()
    start = c.find(sig)
    if start == -1:
        return False
    nextm = c.find("\n.method ", start + 10)
    if nextm == -1:
        nextm = len(c)
    end = c.rfind(".end method", start, nextm)
    if end == -1:
        return False
    with open(path, "w") as f:
        f.write(c[:start] + body + c[end + len(".end method"):])
    return True

# ===== 1. PanelLicense.validate -> always VALID =====
for pattern in ["green/smali*/**/PanelLicense.smali", "green/smali/**/PanelLicense.smali"]:
    for p in glob.glob(pattern, recursive=True):
        body = """.method static validate(Ljava/lang/String;Ljava/lang/String;Z)Lcom/reimod/v39/PanelLicense$Reply;
    .registers 8
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    new-instance v0, Lcom/reimod/v39/PanelLicense$Reply;
    const/4 v1, 0x1
    const-string v2, "Key hop le."
    const-wide v3, 0x7FFFFFFFFFFFFFFFL
    const-string v5, ""
    invoke-direct {v0, v1, v2, v3, v4, v5}, Lcom/reimod/v39/PanelLicense$Reply;-><init>(ILjava/lang/String;JLjava/lang/String;)V
    return-object v0
.end method
"""
        if replace_method(p, ".method static validate(Ljava/lang/String;Ljava/lang/String;Z)Lcom/reimod/v39/PanelLicense$Reply;", body):
            print("[OK] PanelLicense.validate", p)

# ===== 2. ApiLicense.authorize -> always success =====
for pattern in ["green/smali*/**/ApiLicense.smali", "green/smali/**/ApiLicense.smali"]:
    for p in glob.glob(pattern, recursive=True):
        # authorize(String, String)
        body = """.method public static authorize(Ljava/lang/String;Ljava/lang/String;)Lcom/killua/nexo/license/ApiLicense$Result;
    .registers 8
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v0
    const-wide v2, 0x757B12C00L
    add-long v4, v0, v2
    new-instance v6, Lcom/killua/nexo/license/ApiLicense$Result;
    const/4 v7, 0x0
    const/4 v3, 0x0
    const/4 v2, 0x1
    invoke-direct/range {v6 .. v7}, Lcom/killua/nexo/license/ApiLicense$Result;-><init>(JJLjava/lang/String;IZ)V
    return-object v6
.end method
"""
        # Result constructor might be (JJLjava/lang/String;IZ) - check from decompile:
        # Result(long leaseDeadline, long licenseDeadline, String error, int code, boolean knownExpiry)
        body = """.method public static authorize(Ljava/lang/String;Ljava/lang/String;)Lcom/killua/nexo/license/ApiLicense$Result;
    .registers 9
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v0
    const-wide v2, 0x757B12C00L
    add-long/2addr v2, v0
    new-instance v0, Lcom/killua/nexo/license/ApiLicense$Result;
    const/4 v5, 0x0
    const/4 v6, 0x0
    const/4 v7, 0x1
    move-object v1, v0
    move-wide v3, v2
    invoke-direct/range {v1 .. v7}, Lcom/killua/nexo/license/ApiLicense$Result;-><init>(JJLjava/lang/String;IZ)V
    return-object v0
.end method
"""
        if replace_method(p, ".method public static authorize(Ljava/lang/String;Ljava/lang/String;)Lcom/killua/nexo/license/ApiLicense$Result;", body):
            print("[OK] ApiLicense.authorize", p)

        # also fromDecision always valid path
        body2 = """.method public static fromDecision(Lcom/killua/nexo/license/ApiLicense$Decision;JJ)Lcom/killua/nexo/license/ApiLicense$Result;
    .registers 9
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v0
    const-wide v2, 0x757B12C00L
    add-long/2addr v2, v0
    new-instance v0, Lcom/killua/nexo/license/ApiLicense$Result;
    const/4 v5, 0x0
    const/4 v6, 0x0
    const/4 v7, 0x1
    move-object v1, v0
    move-wide v3, v2
    invoke-direct/range {v1 .. v7}, Lcom/killua/nexo/license/ApiLicense$Result;-><init>(JJLjava/lang/String;IZ)V
    return-object v0
.end method
"""
        if replace_method(p, ".method public static fromDecision(Lcom/killua/nexo/license/ApiLicense$Decision;JJ)Lcom/killua/nexo/license/ApiLicense$Result;", body2):
            print("[OK] ApiLicense.fromDecision", p)

# ===== 3. ProxyIntegrity - session always ok, no kill =====
for pattern in ["green/smali*/**/ProxyIntegrity.smali", "green/smali/**/ProxyIntegrity.smali"]:
    for p in glob.glob(pattern, recursive=True):
        with open(p) as f:
            c = f.read()
        changed = False
        for sig, body in [
(".method public static checkSession(Landroid/content/Context;)Z",
".method public static checkSession(Landroid/content/Context;)Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"),
(".method public static checkEnvironment()V",
".method public static checkEnvironment()V\n    .registers 0\n    return-void\n.end method\n"),
(".method public static a(J)Z",
".method public static a(J)Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method\n"),
]:
            start = c.find(sig)
            if start != -1:
                nextm = c.find("\n.method ", start + 10)
                if nextm == -1: nextm = len(c)
                end = c.rfind(".end method", start, nextm)
                c = c[:start] + body + c[end+len(".end method"):]
                changed = True
        if changed:
            open(p,"w").write(c)
            print("[OK] ProxyIntegrity", p)

# ===== 4. NativeGrantPolicy if present - force grant =====
for pattern in ["green/smali*/**/NativeGrantPolicy.smali", "green/smali/**/NativeGrantPolicy.smali"]:
    for p in glob.glob(pattern, recursive=True):
        with open(p) as f:
            c = f.read()
        # force any boolean method that might be grant check to true
        # look for common patterns
        print("[INFO] NativeGrantPolicy found", p)

print("[*] Crack patches done")
