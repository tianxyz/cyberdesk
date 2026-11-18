import hashlib
import hmac
import http.cookies
import os
import secrets
import sqlite3
import urllib.parse
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sistema_web.db")
SESIONES = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            cedula TEXT PRIMARY KEY,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            motivo TEXT NOT NULL DEFAULT 'Sin especificar',
            rol TEXT NOT NULL DEFAULT 'usuario',
            clave_hash TEXT NOT NULL,
            sal TEXT NOT NULL,
            intentos INTEGER NOT NULL DEFAULT 0,
            bloqueado_hasta TEXT
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS equipos (
            codigo TEXT PRIMARY KEY,
            tipo TEXT NOT NULL,
            marca TEXT NOT NULL,
            modelo TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'Disponible'
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS asignaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cedula TEXT NOT NULL REFERENCES usuarios(cedula),
            codigo TEXT NOT NULL UNIQUE REFERENCES equipos(codigo),
            fecha TEXT NOT NULL
        )""")
    conn.commit()
    return conn

def hashear(clave, sal=None):
    sal = sal or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", clave.encode(), bytes.fromhex(sal), 100_000)
    return h.hex(), sal

def verificar_clave(clave, clave_hash, sal):
    return hmac.compare_digest(hashear(clave, sal)[0], clave_hash)

def hay_admin():
    conn = get_db()
    res = conn.execute("SELECT 1 FROM usuarios WHERE rol = 'admin'").fetchone() is not None
    conn.close()
    return res

def limpiar_cedula(ced):
    return "".join(c for c in ced if c.isdigit())

def layout(titulo, contenido, alerta="", tipo_alerta="error"):
    toast_script = ""
    if alerta:
        bg_toast = "bg-red-500/10 border-red-500/30 text-red-400" if tipo_alerta == "error" else "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
        icon = "⚠️" if tipo_alerta == "error" else "✨"
        toast_script = f"""
        <div id="toast-msg" class="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-5 py-4 rounded-2xl border {bg_toast} shadow-2xl backdrop-blur-xl transition-all duration-300 translate-y-0 opacity-100">
            <span class="text-lg">{icon}</span>
            <p class="text-sm font-medium">{alerta}</p>
        </div>
        <script>
            setTimeout(() => {{
                const t = document.getElementById('toast-msg');
                if(t) {{ t.style.opacity = '0'; t.style.transform = 'translateY(1rem)'; setTimeout(() => t.remove(), 300); }}
            }}, 4000);
        </script>"""

    return f"""<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{titulo} | CyberDesk</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>body {{ font-family: 'Plus Jakarta Sans', sans-serif; }}</style>
</head>
<body class="bg-[#090d16] text-slate-100 min-h-screen antialiased selection:bg-indigo-500 selection:text-white">
    {contenido}
    {toast_script}
</body>
</html>"""

def vista_auth(es_setup=False, alerta="", tipo_alerta="error"):
    titulo = "Configuración Inicial" | "Iniciar Sesión" if False else ("Configuración Maestra" if es_setup else "Portal de Acceso")
    subtitulo = "Registra al Administrador principal del sistema." if es_setup else "Introduce tus credenciales para entrar a CyberDesk."
    accion = "/setup" if es_setup else "/login"
    
    campos_extra = ""
    if es_setup:
        campos_extra = """
        <div class="grid grid-cols-2 gap-3">
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Nombre</label>
                <input type="text" name="nombre" required class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Apellido</label>
                <input type="text" name="apellido" required class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
            </div>
        </div>"""

    registro_link = "" if es_setup else """
    <div class="mt-6 pt-6 border-t border-slate-800/60 text-center">
        <a href="/registro" class="text-xs text-indigo-400 hover:text-indigo-300 font-semibold transition">¿No tienes cuenta? Regístrate aquí →</a>
    </div>"""

    html = f"""
    <div class="min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-950/30 via-[#090d16] to-[#090d16]">
        <div class="w-full max-w-md bg-[#0f172a]/80 backdrop-blur-2xl border border-slate-800/80 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
            <div class="absolute -top-24 -right-24 w-48 h-48 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none"></div>
            <div class="flex items-center gap-3.5 mb-8">
                <div class="w-12 h-12 rounded-2xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center font-black text-xl shadow-lg shadow-indigo-500/25">CD</div>
                <div>
                    <h1 class="text-xl font-bold tracking-tight text-white">CyberDesk</h1>
                    <p class="text-xs text-slate-400">{subtitulo}</p>
                </div>
            </div>
            <form method="POST" action="{accion}" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Cédula de Identidad</label>
                    <input type="text" name="cedula" required placeholder="Ej. 28123456" class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
                </div>
                {campos_extra}
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Contraseña</label>
                    <input type="password" name="clave" required placeholder="••••••••" class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
                </div>
                <button type="submit" class="w-full bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-bold py-3 rounded-xl text-sm shadow-lg shadow-indigo-600/25 transition cursor-pointer mt-3">
                    {'Crear Cuenta Maestra' if es_setup else 'Iniciar Sesión'}
                </button>
            </form>
            {registro_link}
        </div>
    </div>"""
    return layout("Acceso", html, alerta, tipo_alerta)

def vista_registro(alerta=""):
    html = f"""
    <div class="min-h-screen flex items-center justify-center p-4 bg-[#090d16]">
        <div class="w-full max-w-md bg-[#0f172a]/80 backdrop-blur-2xl border border-slate-800/80 rounded-3xl p-8 shadow-2xl">
            <h1 class="text-xl font-bold text-white mb-1">Registro de Usuario</h1>
            <p class="text-xs text-slate-400 mb-6">Únete a CyberDesk para gestionar tu hardware.</p>
            <form method="POST" action="/registro" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Cédula (6 a 9 dígitos)</label>
                    <input type="text" name="cedula" required placeholder="Ej. 28123456" class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 focus:outline-none">
                </div>
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Nombre</label>
                        <input type="text" name="nombre" required class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 focus:outline-none">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Apellido</label>
                        <input type="text" name="apellido" required class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 focus:outline-none">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Motivo de solicitud (Opcional)</label>
                    <input type="text" name="motivo" placeholder="Ej. Desarrollo, Laboratorio..." class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 focus:outline-none">
                </div>
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Contraseña (Mín. 6 carac., letras y números)</label>
                    <input type="password" name="clave" required class="w-full bg-[#0d1322] border border-slate-800/80 rounded-xl px-4 py-3 text-sm focus:border-indigo-500 focus:outline-none">
                </div>
                <button type="submit" class="w-full bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-bold py-3 rounded-xl text-sm transition cursor-pointer">Completar Registro</button>
            </form>
            <div class="mt-6 text-center">
                <a href="/" class="text-xs text-slate-400 hover:text-white transition font-medium">← Volver al login</a>
            </div>
        </div>
    </div>"""
    return layout("Registro", html, alerta, "error")

def vista_dashboard(sesion, tab="resumen", alerta="", tipo_alerta="ok"):
    conn = get_db()
    es_admin = sesion["rol"] == "admin"
    
    if es_admin:
        links = [
            ("resumen", "⚡ Dashboard", "M13 10V3L4 14h7v7l9-11h-7z"),
            ("usuarios", "👥 Usuarios", "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"),
            ("equipos", "💻 Inventario", "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"),
            ("asignaciones", "🔄 Asignaciones", "M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4")
        ]
    else:
        links = [
            ("mis_equipos", "💻 Mis Equipos", "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"),
            ("disponibles", "✨ Catálogo Libre", "M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z")
        ]
        if tab == "resumen": tab = "mis_equipos"

    nav_html = ""
    for clave, texto, icono in links:
        activo = "bg-indigo-600/15 text-indigo-400 border border-indigo-500/30 shadow-lg shadow-indigo-500/5 font-semibold" if tab == clave else "text-slate-400 hover:bg-slate-900/60 hover:text-slate-200 font-medium"
        nav_html += f"""
        <a href="/panel?tab={clave}" class="flex items-center gap-3 px-4 py-3 rounded-2xl text-sm transition {activo}">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="{icono}"></path></svg>
            <span>{texto}</span>
        </a>"""

    cuerpo = ""
    if es_admin and tab == "resumen":
        u_tot = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        e_tot = conn.execute("SELECT COUNT(*) FROM equipos").fetchone()[0]
        e_asig = conn.execute("SELECT COUNT(*) FROM equipos WHERE estado='Asignado'").fetchone()[0]
        e_disp = conn.execute("SELECT COUNT(*) FROM equipos WHERE estado='Disponible'").fetchone()[0]
        cuerpo = f"""
        <div class="mb-8">
            <h2 class="text-2xl font-black text-white tracking-tight">Panel de Control 🚀</h2>
            <p class="text-sm text-slate-400 mt-1">Monitoreo en tiempo real de CyberDesk.</p>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl relative overflow-hidden group hover:border-indigo-500/40 transition">
                <div class="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-2xl group-hover:bg-indigo-500/10 transition"></div>
                <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Usuarios Registrados</p>
                <p class="text-4xl font-black text-white mt-3">{u_tot}</p>
            </div>
            <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl relative overflow-hidden group hover:border-blue-500/40 transition">
                <div class="absolute top-0 right-0 w-32 h-32 bg-blue-500/5 rounded-full blur-2xl group-hover:bg-blue-500/10 transition"></div>
                <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Equipos Totales</p>
                <p class="text-4xl font-black text-blue-400 mt-3">{e_tot}</p>
            </div>
            <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl relative overflow-hidden group hover:border-amber-500/40 transition">
                <div class="absolute top-0 right-0 w-32 h-32 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition"></div>
                <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Equipos Asignados</p>
                <p class="text-4xl font-black text-amber-400 mt-3">{e_asig}</p>
            </div>
            <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl relative overflow-hidden group hover:border-emerald-500/40 transition">
                <div class="absolute top-0 right-0 w-32 h-32 bg-emerald-500/5 rounded-full blur-2xl group-hover:bg-emerald-500/10 transition"></div>
                <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Libres / Disponibles</p>
                <p class="text-4xl font-black text-emerald-400 mt-3">{e_disp}</p>
            </div>
        </div>"""

    elif es_admin and tab == "usuarios":
        filas = conn.execute("SELECT cedula, nombre, apellido, motivo, rol FROM usuarios ORDER BY rol, nombre").fetchall()
        trs = "".join([f"""
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/20 transition">
                <td class="py-4 px-5 font-mono text-xs text-indigo-300">{f[0]}</td>
                <td class="py-4 px-5 font-semibold text-white">{f[1]} {f[2]}</td>
                <td class="py-4 px-5 text-slate-400 text-xs">{f[3]}</td>
                <td class="py-4 px-5"><span class="px-3 py-1 rounded-full text-xs font-semibold {'bg-violet-500/10 text-violet-400 border border-violet-500/20' if f[4]=='admin' else 'bg-slate-800 text-slate-300'}">{f[4].upper()}</span></td>
                <td class="py-4 px-5 text-right">
                    {f'<form method="POST" action="/eliminar_usuario" class="inline"><input type="hidden" name="cedula" value="{f[0]}"><button class="text-xs text-red-400 hover:text-red-300 font-semibold cursor-pointer">Eliminar</button></form>' if f[4] != 'admin' else '<span class="text-xs text-slate-600 font-medium">Protegido</span>'}
                </td>
            </tr>""" for f in filas])
        cuerpo = f"""
        <div class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-black text-white">Gestión de Usuarios</h2>
                <p class="text-sm text-slate-400">Control de cuentas vinculadas a CyberDesk.</p>
            </div>
        </div>
        <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 rounded-3xl overflow-hidden shadow-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900/60 text-xs uppercase font-bold tracking-wider text-slate-400 border-b border-slate-800/80">
                    <tr><th class="py-4 px-5">Cédula</th><th class="py-4 px-5">Nombre</th><th class="py-4 px-5">Motivo</th><th class="py-4 px-5">Rol</th><th class="py-4 px-5 text-right">Acción</th></tr>
                </thead>
                <tbody class="divide-y divide-slate-800/40">{trs}</tbody>
            </table>
        </div>"""

    elif es_admin and tab == "equipos":
        filas = conn.execute("SELECT codigo, tipo, marca, modelo, estado FROM equipos ORDER BY codigo").fetchall()
        trs = "".join([f"""
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/20 transition">
                <td class="py-4 px-5 font-mono text-xs text-indigo-400 font-bold">{f[0]}</td>
                <td class="py-4 px-5 text-slate-200">{f[1]}</td>
                <td class="py-4 px-5 font-medium text-white">{f[2]} {f[3]}</td>
                <td class="py-4 px-5"><span class="px-3 py-1 rounded-full text-xs font-semibold {'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' if f[4]=='Disponible' else 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}">{f[4]}</span></td>
                <td class="py-4 px-5 text-right">
                    {f'<form method="POST" action="/eliminar_equipo" class="inline"><input type="hidden" name="codigo" value="{f[0]}"><button class="text-xs text-red-400 hover:text-red-300 font-semibold cursor-pointer">Eliminar</button></form>' if f[4]=='Disponible' else '<span class="text-xs text-slate-600 font-medium">Asignado</span>'}
                </td>
            </tr>""" for f in filas]) or '<tr><td colspan="5" class="py-12 text-center text-slate-500 text-sm">No hay equipos registrados todavía.</td></tr>'
        
        cuerpo = f"""
        <div class="mb-6">
            <h2 class="text-2xl font-black text-white">Inventario de Hardware</h2>
            <p class="text-sm text-slate-400">Añade o da de baja componentes y equipos.</p>
        </div>
        
        <form method="POST" action="/nuevo_equipo" class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl mb-6 grid grid-cols-1 sm:grid-cols-5 gap-4 items-end shadow-xl">
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Código</label>
                <input type="text" name="codigo" placeholder="PC-001" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Tipo</label>
                <input type="text" name="tipo" placeholder="PC / Laptop" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Marca</label>
                <input type="text" name="marca" placeholder="Dell / HP" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Modelo</label>
                <input type="text" name="modelo" placeholder="OptiPlex" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
            </div>
            <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2.5 px-4 rounded-xl text-sm transition cursor-pointer shadow-lg shadow-indigo-600/20">+ Registrar</button>
        </form>

        <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 rounded-3xl overflow-hidden shadow-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900/60 text-xs uppercase font-bold tracking-wider text-slate-400 border-b border-slate-800/80">
                    <tr><th class="py-4 px-5">Código</th><th class="py-4 px-5">Tipo</th><th class="py-4 px-5">Marca y Modelo</th><th class="py-4 px-5">Estado</th><th class="py-4 px-5 text-right">Acción</th></tr>
                </thead>
                <tbody class="divide-y divide-slate-800/40">{trs}</tbody>
            </table>
        </div>"""

    elif es_admin and tab == "asignaciones":
        usuarios = conn.execute("SELECT cedula, nombre, apellido FROM usuarios ORDER BY nombre").fetchall()
        equipos = conn.execute("SELECT codigo, tipo, marca, modelo FROM equipos WHERE estado='Disponible' ORDER BY codigo").fetchall()
        asigs = conn.execute("""
            SELECT a.codigo, e.tipo || ' ' || e.marca || ' ' || e.modelo, u.nombre || ' ' || u.apellido, a.cedula, a.fecha
            FROM asignaciones a JOIN usuarios u ON a.cedula = u.cedula JOIN equipos e ON a.codigo = e.codigo
        """).fetchall()

        opt_u = "".join([f'<option value="{u[0]}">{u[0]} - {u[1]} {u[2]}</option>' for u in usuarios])
        opt_e = "".join([f'<option value="{e[0]}">{e[0]} - {e[1]} {e[2]} {e[3]}</option>' for e in equipos])
        trs = "".join([f"""
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/20 transition">
                <td class="py-4 px-5 font-mono text-xs text-indigo-400 font-bold">{a[0]}</td>
                <td class="py-4 px-5 text-white">{a[1]}</td>
                <td class="py-4 px-5 font-semibold text-slate-200">{a[2]} <span class="text-xs text-slate-500 font-normal">({a[3]})</span></td>
                <td class="py-4 px-5 text-xs text-slate-400">{a[4]}</td>
                <td class="py-4 px-5 text-right">
                    <form method="POST" action="/devolver" class="inline"><input type="hidden" name="codigo" value="{a[0]}"><button class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-xl transition cursor-pointer font-semibold">Devolver</button></form>
                </td>
            </tr>""" for a in asigs]) or '<tr><td colspan="5" class="py-12 text-center text-slate-500 text-sm">No hay asignaciones activas.</td></tr>'

        cuerpo = f"""
        <div class="mb-6">
            <h2 class="text-2xl font-black text-white">Asignaciones de Hardware</h2>
            <p class="text-sm text-slate-400">Entrega equipos libres al personal correspondiente.</p>
        </div>

        <form method="POST" action="/asignar" class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 p-6 rounded-3xl mb-6 grid grid-cols-1 sm:grid-cols-3 gap-4 items-end shadow-xl">
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Seleccionar Usuario</label>
                <select name="cedula" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
                    <option value="">-- Elige un usuario --</option>{opt_u}
                </select>
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 mb-1.5 uppercase">Equipo Disponible</label>
                <select name="codigo" required class="w-full bg-[#0d1322] border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm focus:border-indigo-500 focus:outline-none">
                    <option value="">-- Elige un equipo --</option>{opt_e}
                </select>
            </div>
            <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2.5 px-4 rounded-xl text-sm transition cursor-pointer shadow-lg shadow-indigo-600/20">Asignar Equipo</button>
        </form>

        <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 rounded-3xl overflow-hidden shadow-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900/60 text-xs uppercase font-bold tracking-wider text-slate-400 border-b border-slate-800/80">
                    <tr><th class="py-4 px-5">Código</th><th class="py-4 px-5">Equipo</th><th class="py-4 px-5">Asignado a</th><th class="py-4 px-5">Fecha</th><th class="py-4 px-5 text-right">Acción</th></tr>
                </thead>
                <tbody class="divide-y divide-slate-800/40">{trs}</tbody>
            </table>
        </div>"""

    elif not es_admin and tab == "mis_equipos":
        filas = conn.execute("""
            SELECT a.codigo, e.tipo, e.marca, e.modelo, a.fecha
            FROM asignaciones a JOIN equipos e ON a.codigo = e.codigo WHERE a.cedula = ?
        """, (sesion["cedula"],)).fetchall()
        trs = "".join([f"""
            <tr class="border-b border-slate-800/40">
                <td class="py-4 px-5 font-mono text-xs text-indigo-400 font-bold">{f[0]}</td>
                <td class="py-4 px-5 text-white">{f[1]}</td>
                <td class="py-4 px-5 font-semibold text-slate-200">{f[2]} {f[3]}</td>
                <td class="py-4 px-5 text-xs text-slate-400">{f[4]}</td>
            </tr>""" for f in filas]) or '<tr><td colspan="4" class="py-12 text-center text-slate-500 text-sm">No tienes equipos asignados actualmente.</td></tr>'
        cuerpo = f"""
        <div class="mb-6">
            <h2 class="text-2xl font-black text-white">Mis Equipos Asignados</h2>
            <p class="text-sm text-slate-400">Hardware bajo tu custodia y responsabilidad.</p>
        </div>
        <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 rounded-3xl overflow-hidden shadow-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900/60 text-xs uppercase font-bold tracking-wider text-slate-400 border-b border-slate-800/80">
                    <tr><th class="py-4 px-5">Código</th><th class="py-4 px-5">Tipo</th><th class="py-4 px-5">Equipo</th><th class="py-4 px-5">Desde</th></tr>
                </thead>
                <tbody class="divide-y divide-slate-800/40">{trs}</tbody>
            </table>
        </div>"""

    elif not es_admin and tab == "disponibles":
        filas = conn.execute("SELECT codigo, tipo, marca, modelo FROM equipos WHERE estado='Disponible'").fetchall()
        trs = "".join([f"""
            <tr class="border-b border-slate-800/40">
                <td class="py-4 px-5 font-mono text-xs text-emerald-400 font-bold">{f[0]}</td>
                <td class="py-4 px-5 text-white">{f[1]}</td>
                <td class="py-4 px-5 font-semibold text-slate-200">{f[2]} {f[3]}</td>
                <td class="py-4 px-5"><span class="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Disponible</span></td>
            </tr>""" for f in filas]) or '<tr><td colspan="4" class="py-12 text-center text-slate-500 text-sm">No hay equipos libres en este momento.</td></tr>'
        cuerpo = f"""
        <div class="mb-6">
            <h2 class="text-2xl font-black text-white">Catálogo de Equipos Libres</h2>
            <p class="text-sm text-slate-400">Equipos disponibles en inventario listos para asignación.</p>
        </div>
        <div class="bg-[#0f172a]/60 backdrop-blur-xl border border-slate-800/80 rounded-3xl overflow-hidden shadow-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900/60 text-xs uppercase font-bold tracking-wider text-slate-400 border-b border-slate-800/80">
                    <tr><th class="py-4 px-5">Código</th><th class="py-4 px-5">Tipo</th><th class="py-4 px-5">Marca y Modelo</th><th class="py-4 px-5">Estado</th></tr>
                </thead>
                <tbody class="divide-y divide-slate-800/40">{trs}</tbody>
            </table>
        </div>"""

    conn.close()

    html = f"""
    <div class="min-h-screen flex flex-col md:flex-row">
        <aside class="w-full md:w-72 bg-[#0f172a]/80 backdrop-blur-2xl border-b md:border-b-0 md:border-r border-slate-800/80 p-6 flex flex-col justify-between">
            <div>
                <div class="flex items-center gap-3.5 mb-8 px-2">
                    <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center font-black text-white shadow-lg shadow-indigo-500/25">CD</div>
                    <div>
                        <span class="font-black text-base tracking-tight text-white block">CyberDesk</span>
                        <span class="text-[10px] text-indigo-400 font-bold uppercase tracking-widest">Hardware OS</span>
                    </div>
                </div>
                <nav class="space-y-1.5">{nav_html}</nav>
            </div>
            <div class="pt-6 mt-6 border-t border-slate-800/80">
                <div class="mb-4 px-3">
                    <p class="text-sm font-bold text-white truncate">{sesion['nombre']}</p>
                    <p class="text-xs text-indigo-400 font-semibold capitalize mt-0.5">{sesion['rol']} • <span class="font-mono">{sesion['cedula']}</span></p>
                </div>
                <a href="/logout" class="block w-full text-center py-2.5 px-4 rounded-xl bg-slate-800/60 hover:bg-red-500/15 hover:text-red-400 text-slate-300 text-xs font-bold transition">Cerrar Sesión</a>
            </div>
        </aside>
        <main class="flex-1 p-6 md:p-10 max-w-7xl">
            {cuerpo}
        </main>
    </div>"""
    return layout("Panel de Control", html, alerta, tipo_alerta)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def get_sesion(self):
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            c = http.cookies.SimpleCookie(cookie_header)
            if "token" in c and c["token"].value in SESIONES:
                return SESIONES[c["token"].value]
        return None

    def responder(self, html, cookie=None):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def redirigir(self, ruta, cookie=None):
        self.send_response(302)
        self.send_header("Location", ruta)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def leer_post(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        return {k: v[0].strip() for k, v in urllib.parse.parse_qs(data).items()}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        ruta = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        sesion = self.get_sesion()

        if ruta == "/logout":
            self.redirigir("/", "token=; Path=/; Max-Age=0")
            return

        if not hay_admin():
            self.responder(vista_auth(es_setup=True))
            return

        if ruta == "/registro":
            self.responder(vista_registro())
            return

        if ruta == "/panel":
            if not sesion:
                self.redirigir("/")
                return
            tab = params.get("tab", ["resumen"])[0]
            msg = params.get("msg", [""])[0]
            tipo = params.get("tipo", ["ok"])[0]
            self.responder(vista_dashboard(sesion, tab=tab, alerta=msg, tipo_alerta=tipo))
            return

        if sesion:
            self.redirigir("/panel")
        else:
            self.responder(vista_auth(es_setup=False))

    def do_POST(self):
        ruta = urllib.parse.urlparse(self.path).path
        datos = self.leer_post()
        sesion = self.get_sesion()
        conn = get_db()

        if ruta == "/setup" and not hay_admin():
            ced = limpiar_cedula(datos.get("cedula", ""))
            nom, ape, clave = datos.get("nombre", ""), datos.get("apellido", ""), datos.get("clave", "")
            if not (6 <= len(ced) <= 9) or len(clave) < 8:
                self.responder(vista_auth(True, "La cédula debe tener entre 6 y 9 dígitos y la contraseña mínimo 8 caracteres."))
                return
            h, s = hashear(clave)
            conn.execute("INSERT INTO usuarios (cedula, nombre, apellido, rol, clave_hash, sal) VALUES (?, ?, ?, 'admin', ?, ?)",
                         (ced, nom.title(), ape.title(), h, s))
            conn.commit()
            self.responder(vista_auth(False, "Administrador creado con éxito. Inicia sesión.", "ok"))

        elif ruta == "/registro":
            ced = limpiar_cedula(datos.get("cedula", ""))
            nom, ape, mot, clave = datos.get("nombre", ""), datos.get("apellido", ""), datos.get("motivo", "Sin especificar"), datos.get("clave", "")
            if not (6 <= len(ced) <= 9):
                self.responder(vista_registro("La cédula debe tener entre 6 y 9 dígitos numéricos."))
                return
            if len(clave) < 6 or not (any(c.isalpha() for c in clave) and any(c.isdigit() for c in clave)):
                self.responder(vista_registro("La contraseña debe tener al menos 6 caracteres con letras y números."))
                return
            if conn.execute("SELECT 1 FROM usuarios WHERE cedula=?", (ced,)).fetchone():
                self.responder(vista_registro("Ya existe un usuario con esa cédula."))
                return
            h, s = hashear(clave)
            conn.execute("INSERT INTO usuarios (cedula, nombre, apellido, motivo, rol, clave_hash, sal) VALUES (?, ?, ?, ?, 'usuario', ?, ?)",
                         (ced, nom.title(), ape.title(), mot or "Sin especificar", h, s))
            conn.commit()
            self.responder(vista_auth(False, "Cuenta creada con éxito. Ya puedes iniciar sesión.", "ok"))

        elif ruta == "/login":
            ced = limpiar_cedula(datos.get("cedula", ""))
            clave = datos.get("clave", "")
            u = conn.execute("SELECT * FROM usuarios WHERE cedula=?", (ced,)).fetchone()
            if u and verificar_clave(clave, u[5], u[6]):
                token = secrets.token_hex(16)
                SESIONES[token] = {"cedula": u[0], "nombre": f"{u[1]} {u[2]}", "rol": u[4]}
                self.redirigir("/panel", f"token={token}; Path=/; HttpOnly")
            else:
                self.responder(vista_auth(False, "Cédula o contraseña incorrecta."))

        elif ruta == "/nuevo_equipo" and sesion and sesion["rol"] == "admin":
            cod, tipo, marca, mod = datos["codigo"].upper(), datos["tipo"].title(), datos["marca"].title(), datos["modelo"]
            try:
                conn.execute("INSERT INTO equipos (codigo, tipo, marca, modelo) VALUES (?, ?, ?, ?)", (cod, tipo, marca, mod))
                conn.commit()
                self.redirigir("/panel?tab=equipos&msg=Equipo+registrado+exitosamente")
            except sqlite3.IntegrityError:
                self.redirigir("/panel?tab=equipos&msg=El+codigo+de+equipo+ya+existe&tipo=error")

        elif ruta == "/eliminar_equipo" and sesion and sesion["rol"] == "admin":
            conn.execute("DELETE FROM equipos WHERE codigo=? AND estado='Disponible'", (datos["codigo"],))
            conn.commit()
            self.redirigir("/panel?tab=equipos&msg=Equipo+eliminado+del+inventario")

        elif ruta == "/eliminar_usuario" and sesion and sesion["rol"] == "admin":
            ced = datos["cedula"]
            if conn.execute("SELECT 1 FROM asignaciones WHERE cedula=?", (ced,)).fetchone():
                self.redirigir("/panel?tab=usuarios&msg=El+usuario+tiene+equipos+asignados&tipo=error")
            else:
                conn.execute("DELETE FROM usuarios WHERE cedula=? AND rol!='admin'", (ced,))
                conn.commit()
                self.redirigir("/panel`tab=usuarios&msg=Usuario+eliminado")

        elif ruta == "/asignar" and sesion and sesion["rol"] == "admin":
            ced, cod = datos.get("cedula"), datos.get("codigo")
            if ced and cod:
                conn.execute("INSERT INTO asignaciones (cedula, codigo, fecha) VALUES (?, ?, ?)", (ced, cod, str(date.today())))
                conn.execute("UPDATE equipos SET estado='Asignado' WHERE codigo=?", (cod,))
                conn.commit()
                self.redirigir("/panel?tab=asignaciones&msg=Equipo+asignado+correctamente")
            else:
                self.redirigir("/panel?tab=asignaciones&msg=Debes+elegir+usuario+y+equipo&tipo=error")

        elif ruta == "/devolver" and sesion and sesion["rol"] == "admin":
            cod = datos["codigo"]
            conn.execute("DELETE FROM asignaciones WHERE codigo=?", (cod,))
            conn.execute("UPDATE equipos SET estado='Disponible' WHERE codigo=?", (cod,))
            conn.commit()
            self.redirigir("/panel?tab=asignaciones&msg=Equipo+devuelto+exitosamente")

        conn.close()

if __name__ == "__main__":
    PUERTO = int(os.environ.get("PORT", 8000))
    servidor = HTTPServer(("0.0.0.0", PUERTO), Handler)
    print(f"CyberDesk activo en el puerto {PUERTO}")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor apagado con éxito.")
