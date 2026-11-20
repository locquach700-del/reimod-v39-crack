import os, glob, sys, re

print("[*] REIMOD V39 crack")

# ===== Fix manifest: remove unknown attributes =====
mf = "green/AndroidManifest.xml"
if os.path.isfile(mf):
    with open(mf, encoding="utf-8", errors="ignore") as f:
        m = f.read()
    m2 = re.sub(r'\s*android:pageSizeCompat="[^"]*"', '', m)
    m2 = re.sub(r'\s*android:[a-zA-Z0-9_]*Compat="[^"]*"', '', m2)
    if m2 != m:
        open(mf, "w", encoding="utf-8").write(m2)
        print("[OK] stripped unknown manifest attrs")

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

# ===== PanelLicense.validate =====
for pattern in ["green/smali*/**/PanelLicense.smali", "green/smali/**/PanelLicense.smali"]:
    for p in glob.glob(pattern, recursive=True):
        body = """.method static validate(Ljava/lang/String;Ljava/lang/String;Z)Lcom/reimod/v39/PanelLicense$Reply;
    .registers 8

    new-instance v0, Lcom/reimod/v39/PanelLicense$Reply;
    const/4 v1, 0x1
    const-string v2, "Key hop le."
    const-wide v3, 0x7FFFFFFFFFFFFFFFL
    const-string v5, ""
    invoke-direct/range {v0 .. v5}, Lcom/reimod/v39/PanelLicense$Reply;-><init>(ILjava/lang/String;JLjava/lang/String;)V
    return-object v0
.end method
"""
        if replace_method(p, ".method static validate(Ljava/lang/String;Ljava/lang/String;Z)Lcom/reimod/v39/PanelLicense$Reply;", body):
            print("[OK] PanelLicense.validate", p)

# ===== ApiLicense =====
for pattern in ["green/smali*/**/ApiLicense.smali", "green/smali/**/ApiLicense.smali"]:
    for p in glob.glob(pattern, recursive=True):
        body = """.method public static authorize(Ljava/lang/String;Ljava/lang/String;)Lcom/killua/nexo/license/ApiLicense$Result;
    .registers 9

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v1
    const-wide v3, 0x757B12C00L
    add-long/2addr v3, v1
    new-instance v0, Lcom/killua/nexo/license/ApiLicense$Result;
    move-wide v1, v3
    const/4 v5, 0x0
    const/4 v6, 0x0
    const/4 v7, 0x1
    invoke-direct/range {v0 .. v7}, Lcom/killua/nexo/license/ApiLicense$Result;-><init>(JJLjava/lang/String;IZ)V
    return-object v0
.end method
"""
        if replace_method(p, ".method public static authorize(Ljava/lang/String;Ljava/lang/String;)Lcom/killua/nexo/license/ApiLicense$Result;", body):
            print("[OK] ApiLicense.authorize", p)

        body2 = """.method public static fromDecision(Lcom/killua/nexo/license/ApiLicense$Decision;JJ)Lcom/killua/nexo/license/ApiLicense$Result;
    .registers 9

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v1
    const-wide v3, 0x757B12C00L
    add-long/2addr v3, v1
    new-instance v0, Lcom/killua/nexo/license/ApiLicense$Result;
    move-wide v1, v3
    const/4 v5, 0x0
    const/4 v6, 0x0
    const/4 v7, 0x1
    invoke-direct/range {v0 .. v7}, Lcom/killua/nexo/license/ApiLicense$Result;-><init>(JJLjava/lang/String;IZ)V
    return-object v0
.end method
"""
        if replace_method(p, ".method public static fromDecision(Lcom/killua/nexo/license/ApiLicense$Decision;JJ)Lcom/killua/nexo/license/ApiLicense$Result;", body2):
            print("[OK] ApiLicense.fromDecision", p)

# ===== ProxyIntegrity =====
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

print("[*] Done")
