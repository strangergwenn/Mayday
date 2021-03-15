@echo off

set build="build/Win64"
if not exist "%build%" mkdir %build%
pushd %build%

cmake -G "Visual Studio 16 2019" -A "x64" "%~dp0" 

popd
