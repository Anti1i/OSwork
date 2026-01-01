#!/bin/bash
# 正确的编译顺序

echo "Step 1: Building kernel and boot loader..."
make image

echo ""
echo "Step 2: Installing commands..."
cd command
make install
cd ..

echo ""
echo "Build complete! You can now run: bochs"
