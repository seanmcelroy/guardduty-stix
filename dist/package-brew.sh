#!/bin/sh

# Clean the dist directory
rm -rf *-temp*
rm -f guardduty-stix-*.tgz
rm -f guardduty-stix-*.zip

# Update version
VERSION=$(cat ./VERSION)
cp ../guardduty-stix.csproj ./guardduty-stix.csproj.bak
cat ./guardduty-stix.csproj.bak | sed "s/<Version>[^\<]*<\/Version>/<Version>${VERSION}<\/Version>/" > ../guardduty-stix.csproj

## OSX

# Prep
mkdir -p osx-x64-temp
# Build self-contained executable
dotnet publish --self-contained -c Release -r osx-x64 -o ./dist/osx-x64-temp ../guardduty-stix.csproj 
# Tar it for release to GitHub
tar -cvzf ./guardduty-stix-osx-x64-${VERSION}.tgz ./osx-x64-temp/
# Clean up
rm -rf osx-x64-temp

## WIN PORTABLE

# Prep
mkdir -p win-x64-temp
# Build self-contained executable
dotnet publish --self-contained -c Release -r win-x64 -o ./dist/win-x64-temp ../guardduty-stix.csproj 
# Tar it for release to GitHub
zip ./guardduty-stix-win-x64-${VERSION}.zip ./win-x64-temp/*
# Clean up
rm -rf win-x64-temp

## WIN PORTABLE

# Prep
mkdir -p win-x64-temp
# Build self-contained executable
dotnet publish --self-contained -c Release -r win-x64 -o ./dist/win-x64-temp ../guardduty-stix.csproj 
# Tar it for release to GitHub
zip ./guardduty-stix-win-x64-${VERSION}.zip ./win-x64-temp/*
# Clean up
rm -rf win-x64-temp

## LINUX PORTABLE

# Prep
mkdir -p linux-x64-temp
# Build self-contained executable
dotnet publish --self-contained -c Release -r linux-x64 -o ./dist/linux-x64-temp ../guardduty-stix.csproj 
# Tar it for release to GitHub
tar -cvzf ./guardduty-stix-linux-x64-${VERSION}.tgz ./linux-x64-temp/
# Clean up
rm -rf linux-x64-temp

## CLEANUP
rm -f ./guardduty-stix.csproj.bak
