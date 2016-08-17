#!/usr/bin/env bash

here=$(pwd)

clean () {
  if [[ -d "pywb/build" ]]; then
    echo cleaning build
    rm -rf pywb/build
  fi

  if [[ -d "pywb/dist"  ]]; then
    echo cleaning dist
    rm -rf pywb/dist
  fi

  if [[ -d "pywb/__pycache__"  ]]; then
    echo cleaning pycache
    rm -rf pywb/__pycache__
  fi
}

clean

if [[ -d "temp" ]]; then
  rm -rf temp
fi

mkdir -p temp/pywb


tempDir="$here/temp/pywb"

cd pywb

for fname in `ls *.spec`
do
  base=$(basename "$fname")
  echo "$base"
  pyinstaller $base
  filename="${base%.*}"
  echo ${filename}

  if [[ "$filename" == "wayback" ]]; then
      chmod a+x "dist/pywb/pywb"
      cp -RT dist/pywb ${tempDir}
  else
      chmod a+x "dist/$filename/$filename"
      cp "dist/$filename/$filename" $tempDir
  fi
done

cd $here

clean
#
# cd ${here}
#
#
#
#
#
# cp -RT

# pyinstaller cdx-server.spec

# chmod a+x dist/pywb/cdx-server

# cp -RT dist/pywb  ~/Desktop/pywb
