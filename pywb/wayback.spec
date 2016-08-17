# -*- mode: python -*-

block_cipher = None

added_files = [
  ('/home/john/Desktop/pywbModules/pywb/*.yaml', '.'),
  ('/home/john/Desktop/pywbModules/static','static'),
  ('/home/john/Desktop/pywbModules/templates','templates'),
  ('/home/john/Desktop/pywbModules/sample_archive','sample_archive'),
]

a = Analysis(['wayback.py'],
             pathex=['/home/john/Desktop/pywbModules/pywb'],
             binaries=None,
             datas=added_files,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='wayback',
          debug=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='pywb')
