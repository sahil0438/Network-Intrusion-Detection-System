# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('static', 'static'), 
        ('templates', 'templates')
],
    hiddenimports=[
        'netifaces',  # Crucial for interface detection
        'scapy.all',  # Scapy's main module
        'flask',      # Flask itself
        'socket',     # Often used by Scapy/network operations
        'platform',   # Used for OS detection
        'subprocess', # Used for iptables/netsh calls
        're',         # Used for regex patterns
        'binascii',   # Used for hex conversions
        'tempfile',   # Used for temporary PCAP files
        'collections',# Used for deque, defaultdict
        'datetime',   # Used for timestamps
        'threading',  # Used for background tasks
        'time',       # Used for time operations
        'json'   
],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetSecure',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
