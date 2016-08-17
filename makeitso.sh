#!/usr/bin/env bash

if [[ -d "build"  ]]; then
  echo cleaning build
  rm -rf build
fi

if [[ -d "dist"  ]]; then
  echo cleaning dist
  rm -rf dist
fi

if [[ -d "__pycache__"  ]]; then
  echo cleaning pycache
  rm -rf __pycache__
fi

pyinstaller --console -D wayback.spec

chmod a+x dist/pywb/wayback

cp -RT dist/pywb  ~/Desktop/pywb
