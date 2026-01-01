#!/bin/bash
git add .
git commit -m "update blog $(date)"
git push origin main
echo "--------------------------"
echo "推送成功！代码已上云。"
