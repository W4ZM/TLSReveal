@echo off
set "folder=build"
if not exist "%folder%\" (
    mkdir "%folder%"
)

cd /d "%folder%"
del *.* /F /Q
cmake ..
cmake --build . --config Release


