import os, glob, sys, re

print("[*] REIMOD V39 crack + full VN")

# ===== Fix manifest =====
mf = "green/AndroidManifest.xml"
if os.path.isfile(mf):
    with open(mf, encoding="utf-8", errors="ignore") as f:
        m = f.read()
    m2 = re.sub(r'\s*android:pageSizeCompat="[^"]*"', '', m)
    m2 = re.sub(r'\s*android:[a-zA-Z0-9_]*Compat="[^"]*"', '', m2)
    if m2 != m:
        open(mf, "w", encoding="utf-8").write(m2)
        print("[OK] manifest cleaned")

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

print("[*] Security done")

# ===== FULL VN (const-string only) =====
replacements = [
    # Key / license
    ("Digite uma Key válida.", "Nhập key hợp lệ."),
    ("Digite o código", "Nhập mã"),
    ("Digite o c", "Nhập mã"),
    ("Key inválida, expirada ou bloqueada.", "Key không hợp lệ, hết hạn hoặc bị khóa."),
    ("Key expirada.", "Key hết hạn."),
    ("Key válida.", "Key hợp lệ."),
    ("Key hop le.", "Key hợp lệ."),
    ("Você está usando uma key errada.", "Bạn đang dùng key sai."),
    ("usando uma key errada.", "đang dùng key sai."),
    ("Essa key expirou. Entre com outra key.", "Key này hết hạn. Nhập key khác."),
    ("Essa key atingiu o limite de aparelhos.", "Key đã hết lượt thiết bị."),
    ("Essa key está travada para este aparelho.", "Key bị khóa trên máy này."),
    ("travada para este aparelho.", "bị khóa trên máy này."),
    ("Este aparelho não está ativado para essa key.", "Máy này chưa kích hoạt key."),
    ("ativado para essa key.", "đã kích hoạt cho key này."),
    ("Entre com outra key para continuar.", "Nhập key khác để tiếp tục."),
    ("A chave expirou", "Key đã hết hạn"),
    ("Validade da key", "Hạn dùng key"),
    ("Não foi possível validar sua Key online. Confira sua conexão e tente novamente.", "Không xác thực được key online. Kiểm tra mạng."),
    ("Não foi possível estabelecer a sessão online.", "Không tạo được phiên online."),
    ("Não foi possível identificar este aparelho.", "Không nhận diện được máy này."),
    ("Resposta inválida da API de Keys.", "Phản hồi API key không hợp lệ."),
    ("Resposta inconsistente da API.", "Phản hồi API không nhất quán."),
    ("Endereço da API inválido.", "Địa chỉ API không hợp lệ."),
    ("Atualize o app para continuar.", "Cập nhật app để tiếp tục."),
    ("Atualize o REIMOD V39", "Cập nhật REIMOD V39"),
    ("Instale o APK oficial do REIMOD V39", "Cài APK chính thức REIMOD V39"),

    # Buttons / menu
    ("ABRIR MENU", "MỞ MENU"),
    ("ABRIR PAINEL", "MỞ BẢNG ĐIỀU KHIỂN"),
    ("ABRIR JOGO", "MỞ GAME"),
    ("ABRIR FREE FIRE NORMAL", "MỞ FREE FIRE THƯỜNG"),
    ("ABRIR SHIZUKU", "MỞ SHIZUKU"),
    ("Abrir menu", "Mở menu"),
    ("Abrir painel", "Mở bảng điều khiển"),
    ("Abrir ", "Mở "),
    ("ATIVAR", "BẬT"),
    ("ATUALIZA", "CẬP NHẬT"),
    ("Voltar", "Quay lại"),
    ("PRONTO", "SẴN SÀNG"),
    ("Conectado", "Đã kết nối"),
    ("conectado", "đã kết nối"),
    ("Conecte pelo REIMOD V39", "Kết nối qua REIMOD V39"),
    ("ADB conectado y verificado", "ADB đã kết nối và xác minh"),
    ("ADB desconectado", "ADB mất kết nối"),

    # Status / messages
    ("Arquivos prontos. Toque em Abrir menu.", "File sẵn sàng. Bấm Mở menu."),
    ("Toque em Abrir painel novamente.", "Bấm Mở bảng điều khiển lần nữa."),
    ("Painel flutuante", "Bảng nổi"),
    ("Painel e m", "Bảng và m"),
    ("aguardando valida", "đang chờ xác thực"),
    ("Aguarde a conclus", "Vui lòng đợi hoàn tất"),
    ("Aguarde a conex", "Vui lòng đợi kết nối"),
    ("instalado", "đã cài"),
    ("instalado.", "đã cài."),
    ("desativado neste aparelho.", "đã tắt trên máy này."),
    ("sendo preparado. Confira o status em Conectar.", "đang chuẩn bị. Xem trạng thái ở Kết nối."),
    ("Autorize a VPN em Abrir painel.", "Cho phép VPN ở Mở bảng điều khiển."),
    ("WhatsApp Oficial de Atualiza", "WhatsApp chính thức cập nhật"),
    ("Failed to integrate Cheat Module", "Tích hợp module thất bại"),
    ("Integrate Module", "Tích hợp module"),
    ("Integration interrupted. Tap Integrate Cheat Module to reinstall.", "Tích hợp bị gián đoạn. Bấm Tích hợp module để cài lại."),
    ("Could not start integration wipe", "Không bắt đầu xóa tích hợp được"),
    ("Permission denied. Open Shizuku and authorize REIMOD V39", "Từ chối quyền. Mở Shizuku và cấp quyền REIMOD V39"),
    ("Shizuku lost connection or permission. Re-authorize.", "Shizuku mất kết nối hoặc quyền. Cấp lại."),
    ("Connect and authorize selected method to clear integration", "Kết nối và cấp quyền để xóa tích hợp"),
    ("Connect and authorize ADB or Shizuku to integrate REIMOD V39", "Kết nối ADB hoặc Shizuku để tích hợp REIMOD V39"),

    # Common PT
    ("Erro", "Lỗi"),
    ("Sucesso", "Thành công"),
    ("Cancelar", "Hủy"),
    ("Confirmar", "Xác nhận"),
    ("Sair", "Thoát"),
    ("Fechar", "Đóng"),
    ("Tentar novamente", "Thử lại"),
    ("Aguarde", "Vui lòng đợi"),
    ("Carregando", "Đang tải"),
    ("Processando", "Đang xử lý"),
    ("Concluído", "Hoàn thành"),
    ("Falhou", "Thất bại"),
    ("Instalar", "Cài đặt"),
    ("Atualizar", "Cập nhật"),
    ("Configurações", "Cài đặt"),
    ("Permissão", "Quyền"),
    ("Permissão negada", "Bị từ chối quyền"),
    ("Sem internet", "Không có mạng"),
    ("Verifique sua conexão", "Kiểm tra kết nối mạng"),
    ("Tente novamente mais tarde", "Thử lại sau"),
    ("Algo deu errado", "Đã xảy ra lỗi"),
    ("Ativar", "Bật"),
    ("Desativar", "Tắt"),
    ("Ligado", "Bật"),
    ("Desligado", "Tắt"),
    ("Status", "Trạng thái"),
    ("Versão", "Phiên bản"),
    ("Sobre", "Giới thiệu"),
    ("Ajuda", "Trợ giúp"),
    ("Canal", "Kênh"),
    ("Grupo", "Nhóm"),
    ("Baixar", "Tải xuống"),
    ("Novo", "Mới"),
    ("Pronto", "Sẵn sàng"),
    ("Aguardando", "Đang chờ"),
    ("Conectando", "Đang kết nối"),
    ("Desconectado", "Mất kết nối"),
]

def translate_const_strings(content, pairs):
    def replacer(m):
        full = m.group(0)
        q1, q2 = full.find('"'), full.rfind('"')
        if q1 < 0 or q2 <= q1:
            return full
        prefix, s, suffix = full[:q1+1], full[q1+1:q2], full[q2:]
        for old, new in pairs:
            if old in s:
                s = s.replace(old, new)
        return prefix + s + suffix
    return re.sub(r'const-string(?:/jumbo)?\s+v\d+,\s*".*?"', replacer, content)

count = 0
for root, dirs, files in os.walk("green"):
    for name in files:
        if not name.endswith(".smali"):
            continue
        full = os.path.join(root, name)
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            newc = translate_const_strings(content, replacements)
            if newc != content:
                open(full, "w", encoding="utf-8").write(newc)
                count += 1
        except Exception:
            pass
print(f"[OK] VN translation ({count} files)")
print("[*] Done")
