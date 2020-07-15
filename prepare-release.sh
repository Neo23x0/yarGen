#!/bin/bash

RELDIR=./release
OUTDIR=$RELDIR/yarGen/

cp yarGen.py $OUTDIR
cp -r 3rdparty $OUTDIR
cp -r lib $OUTDIR
cp README.md $OUTDIR
cp LICENSE $OUTDIR

cd $RELDIR
tar -cvzf yarGen.tar.gz ./yarGen/
cd ..